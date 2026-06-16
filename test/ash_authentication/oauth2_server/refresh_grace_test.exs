# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.RefreshGraceTest do
  @moduledoc """
  Refresh-token rotation grace window (`:refresh_token_grace_seconds`) and
  RFC 8252 loopback redirect matching.

  The grace window lets a client re-present a *just-rotated* parent refresh
  token for a short overlap — a lost-response retry or a concurrent
  double-refresh — and get a fresh access token (with the same refresh
  token echoed back) instead of tripping reuse detection and revoking the
  whole chain. `grace == 0` (the default) keeps strict OAuth 2.1 §4.3.1
  behavior.
  """
  use ExUnit.Case, async: false

  require Ash.Query

  alias AshAuthentication.Oauth2Server.{Authorize, PKCE, Register, Token}
  alias Oauth2ServerTest.{GraceServer, OAuthRefreshToken, Server, User}

  alias Oauth2ServerTest.{
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthConsent
  }

  @ctx %{private: %{ash_authentication?: true}}

  setup do
    for resource <- [OAuthClient, OAuthAuthorizationCode, OAuthRefreshToken, OAuthConsent, User] do
      Ash.bulk_destroy!(resource, :destroy, %{}, return_errors?: true)
    end

    user =
      User
      |> Ash.Changeset.for_create(:create, %{email: "alice@example.com"})
      |> Ash.create!()

    {:ok, user: user}
  end

  # ── helpers ────────────────────────────────────────────────────────────

  defp pkce_pair do
    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    {verifier, PKCE.challenge(verifier)}
  end

  defp authorize_params(server, client, challenge, redirect_uri) do
    %{
      "response_type" => "code",
      "client_id" => client.id,
      "redirect_uri" => redirect_uri,
      "code_challenge" => challenge,
      "code_challenge_method" => "S256",
      "scope" => "mcp",
      "state" => "csrf-state",
      "resource" => server.resource_url()
    }
  end

  defp refresh_params(server, client, rt) do
    %{
      "grant_type" => "refresh_token",
      "refresh_token" => rt,
      "client_id" => client.id,
      "resource" => server.resource_url()
    }
  end

  # Register a client and run a full auth-code exchange so we hold a live
  # first-generation refresh token for `server`.
  defp seed_first_refresh(server, user) do
    {:ok, client, _} =
      Register.register(server, %{
        "client_name" => "Grace Client",
        "redirect_uris" => ["https://chat.example.com/cb"]
      })

    {verifier, challenge} = pkce_pair()

    {:ok, validated} =
      Authorize.validate_request(
        server,
        authorize_params(server, client, challenge, "https://chat.example.com/cb")
      )

    code = Authorize.issue_code!(server, user, validated)

    {:ok, first} =
      Token.exchange_authorization_code(server, %{
        "grant_type" => "authorization_code",
        "code" => code.id,
        "redirect_uri" => "https://chat.example.com/cb",
        "code_verifier" => verifier,
        "client_id" => client.id,
        "resource" => server.resource_url()
      })

    {client, first}
  end

  defp rewind_rotated_at(raw, seconds) do
    hash = :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)

    OAuthRefreshToken
    |> Ash.Query.filter(token_hash == ^hash)
    |> Ash.read_one!(context: @ctx)
    |> Ash.Changeset.for_update(:test_set_rotated_at, %{
      rotated_at: DateTime.add(DateTime.utc_now(), seconds, :second)
    })
    |> Ash.update!(context: @ctx)
  end

  defp chain_rows do
    OAuthRefreshToken |> Ash.read!(context: @ctx)
  end

  defp register_loopback(redirect_uri) do
    {:ok, client, _} =
      Register.register(Server, %{
        "client_name" => "Native",
        "redirect_uris" => [redirect_uri]
      })

    client
  end

  # ── grace window ─────────────────────────────────────────────────────────

  describe "refresh-token rotation grace window" do
    test "within grace, reusing the rotated parent echoes it back with a fresh access token",
         %{user: user} do
      {client, first} = seed_first_refresh(GraceServer, user)

      assert {:ok, second} =
               Token.exchange_refresh_token(
                 GraceServer,
                 refresh_params(GraceServer, client, first.refresh_token)
               )

      assert second.refresh_token != first.refresh_token

      # Immediately reusing the parent (well inside the 10s window): 200 with
      # a fresh access token and the SAME refresh token echoed back.
      assert {:ok, grace} =
               Token.exchange_refresh_token(
                 GraceServer,
                 refresh_params(GraceServer, client, first.refresh_token)
               )

      assert grace.refresh_token == first.refresh_token
      assert is_binary(grace.access_token) and grace.access_token != ""
      assert grace.access_token != second.access_token
      assert grace.token_type == "Bearer"
      assert grace.expires_in == GraceServer.access_token_lifetime()

      # The real successor still rotates normally — no chain revocation.
      assert {:ok, third} =
               Token.exchange_refresh_token(
                 GraceServer,
                 refresh_params(GraceServer, client, second.refresh_token)
               )

      assert third.refresh_token != second.refresh_token
    end

    test "within grace, repeated parent reuse is idempotent — no new rows, no revocation",
         %{user: user} do
      {client, first} = seed_first_refresh(GraceServer, user)

      assert {:ok, _second} =
               Token.exchange_refresh_token(
                 GraceServer,
                 refresh_params(GraceServer, client, first.refresh_token)
               )

      assert length(chain_rows()) == 2

      for _ <- 1..3 do
        assert {:ok, grace} =
                 Token.exchange_refresh_token(
                   GraceServer,
                   refresh_params(GraceServer, client, first.refresh_token)
                 )

        assert grace.refresh_token == first.refresh_token
      end

      rows = chain_rows()
      assert length(rows) == 2
      assert Enum.all?(rows, &is_nil(&1.revoked_at))
    end

    test "beyond grace, reusing the parent is detected as reuse and revokes the chain",
         %{user: user} do
      {client, first} = seed_first_refresh(GraceServer, user)

      assert {:ok, second} =
               Token.exchange_refresh_token(
                 GraceServer,
                 refresh_params(GraceServer, client, first.refresh_token)
               )

      # Push the parent's rotation an hour into the past — outside the window.
      rewind_rotated_at(first.refresh_token, -3600)

      assert {:error, :reuse} =
               Token.exchange_refresh_token(
                 GraceServer,
                 refresh_params(GraceServer, client, first.refresh_token)
               )

      assert {:error, :revoked} =
               Token.exchange_refresh_token(
                 GraceServer,
                 refresh_params(GraceServer, client, second.refresh_token)
               )
    end

    test "a revoked chain is never resurrected, even within the grace window", %{user: user} do
      {client, first} = seed_first_refresh(GraceServer, user)

      assert {:ok, _second} =
               Token.exchange_refresh_token(
                 GraceServer,
                 refresh_params(GraceServer, client, first.refresh_token)
               )

      # Explicit RFC 7009 revocation of the chain while the parent is still
      # inside the grace window.
      :ok = Token.revoke(GraceServer, %{"token" => first.refresh_token, "client_id" => client.id})

      assert {:error, :revoked} =
               Token.exchange_refresh_token(
                 GraceServer,
                 refresh_params(GraceServer, client, first.refresh_token)
               )
    end

    test "within grace, a client/resource mismatch wins over the grace echo", %{user: user} do
      {client, first} = seed_first_refresh(GraceServer, user)

      assert {:ok, _second} =
               Token.exchange_refresh_token(
                 GraceServer,
                 refresh_params(GraceServer, client, first.refresh_token)
               )

      wrong_client =
        %{
          refresh_params(GraceServer, client, first.refresh_token)
          | "client_id" => Ash.UUIDv7.generate()
        }

      assert {:error, :client_mismatch} =
               Token.exchange_refresh_token(GraceServer, wrong_client)

      wrong_resource =
        %{
          refresh_params(GraceServer, client, first.refresh_token)
          | "resource" => "https://evil.example.com/mcp"
        }

      assert {:error, :resource_mismatch} =
               Token.exchange_refresh_token(GraceServer, wrong_resource)
    end

    test "with grace 0 (the default), any reuse of a rotated token revokes the chain",
         %{user: user} do
      {client, first} = seed_first_refresh(Server, user)

      assert {:ok, second} =
               Token.exchange_refresh_token(
                 Server,
                 refresh_params(Server, client, first.refresh_token)
               )

      assert {:error, :reuse} =
               Token.exchange_refresh_token(
                 Server,
                 refresh_params(Server, client, first.refresh_token)
               )

      assert {:error, :revoked} =
               Token.exchange_refresh_token(
                 Server,
                 refresh_params(Server, client, second.refresh_token)
               )
    end
  end

  # ── loopback redirect matching (RFC 8252) ─────────────────────────────────

  describe "loopback redirect matching (RFC 8252)" do
    test "a loopback client may authorize from a different port" do
      client = register_loopback("http://127.0.0.1:51999/callback")
      {_v, challenge} = pkce_pair()

      assert {:ok, _} =
               Authorize.validate_request(
                 Server,
                 authorize_params(Server, client, challenge, "http://127.0.0.1:62000/callback")
               )
    end

    test "a loopback client with a different path is rejected" do
      client = register_loopback("http://127.0.0.1:51999/callback")
      {_v, challenge} = pkce_pair()

      assert {:error, :bad_redirect_uri} =
               Authorize.validate_request(
                 Server,
                 authorize_params(Server, client, challenge, "http://127.0.0.1:62000/other")
               )
    end

    test "loopback host stays exact — localhost is not 127.0.0.1" do
      client = register_loopback("http://localhost:4000/cb")
      {_v, challenge} = pkce_pair()

      assert {:error, :bad_redirect_uri} =
               Authorize.validate_request(
                 Server,
                 authorize_params(Server, client, challenge, "http://127.0.0.1:4000/cb")
               )
    end

    test "non-loopback redirects still require an exact port match" do
      client = register_loopback("https://chat.example.com/cb")
      {_v, challenge} = pkce_pair()

      assert {:error, :bad_redirect_uri} =
               Authorize.validate_request(
                 Server,
                 authorize_params(Server, client, challenge, "https://chat.example.com:8443/cb")
               )
    end
  end
end
