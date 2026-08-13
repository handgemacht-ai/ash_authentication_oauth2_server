# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Instant do
  @moduledoc """
  A named value object for an absolute instant in time.

  The OAuth2 server shuttles one concept — an absolute expiry / not-before
  instant — between two representations: `DateTime.t()` in the Ash resource
  layer (storage pinned to `:utc_datetime_usec` for `expires_at`) and
  unix-second integers in JWT claims (`exp`, `iat`, `nbf`). This module owns
  that concept with a single internal `DateTime.t()` representation:

    * `to_unix/1` is used only at the JWT claim boundary (mint writes,
      `check_exp` / `check_nbf` reads).
    * `to_datetime/1` is used only where a data-layer filter or resource
      attribute needs the raw `DateTime.t()`.
    * `expired?/2` replaces the inline `DateTime.compare(DateTime.utc_now(),
      expires_at) == :gt` checks on the resource side.

  It does not change any wire format or comparison precision: JWT-claim
  comparisons stay in unix seconds (via `to_unix/1`), and resource-attribute
  comparisons stay in `DateTime` space (via `expired?/2`).
  """

  @type t :: %__MODULE__{at: DateTime.t()}
  defstruct at: nil

  @doc "The current instant."
  @spec now() :: t()
  def now, do: %__MODULE__{at: DateTime.utc_now()}

  @doc """
  Build an instant from a unix-second integer — e.g. a deserialized JWT
  `exp` / `nbf` claim.
  """
  @spec from_unix(integer()) :: t()
  def from_unix(unix) when is_integer(unix), do: %__MODULE__{at: DateTime.from_unix!(unix)}

  @doc "Wrap an existing `DateTime.t()` — e.g. a resource `expires_at` attribute."
  @spec from_datetime(DateTime.t()) :: t()
  def from_datetime(%DateTime{} = at), do: %__MODULE__{at: at}

  @doc "Add `seconds` (integer) to an instant, returning a new instant."
  @spec add(t(), integer()) :: t()
  def add(%__MODULE__{at: at}, seconds),
    do: %__MODULE__{at: DateTime.add(at, seconds, :second)}

  @doc "Unix-second projection — used only at the JWT claim boundary."
  @spec to_unix(t()) :: integer()
  def to_unix(%__MODULE__{at: at}), do: DateTime.to_unix(at)

  @doc """
  Raw `DateTime.t()` projection — used where a data-layer filter or resource
  attribute needs the underlying datetime.
  """
  @spec to_datetime(t()) :: DateTime.t()
  def to_datetime(%__MODULE__{at: at}), do: at

  @doc """
  True when `instant` (plus `skew` seconds of leeway) is strictly in the past
  relative to now — i.e. the instant has expired.

  Matches the strict-`>` resource-side check
  `DateTime.compare(DateTime.utc_now(), expires_at) == :gt` previously
  inlined in `Token.check_not_expired/1` and `Token.classify_row/5`. The JWT
  `exp` / `nbf` checks keep their unix-second comparison (via `to_unix/1`)
  because their `>=` boundary semantics differ from this strict-`>` form.
  """
  @spec expired?(t(), non_neg_integer()) :: boolean()
  def expired?(%__MODULE__{at: at}, skew) do
    DateTime.compare(DateTime.utc_now(), DateTime.add(at, skew, :second)) == :gt
  end
end
