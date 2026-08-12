# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ScopeSet do
  @moduledoc """
  A typed set of OAuth scopes, replacing the bare space-delimited
  `String.t()` that was re-parsed into a `MapSet` at every site needing
  set semantics.

  ## Why this exists

  The wire format for scopes is a single space-delimited `String.t()` at
  every OAuth 2.1 protocol boundary — the `scope` authorize parameter,
  the `scope` JWT claim, the `scope` token-response field, and the `scope`
  attribute on consent / authorization-code / refresh-token resources.
  Internally, though, the server needs set operations: is every
  requested scope in the catalogue? does a stored consent cover a new
  request? is a given scope present?

  Before this module, each of those sites re-derived a `MapSet` from the
  string with `String.split(" ", trim: true) |> MapSet.new()`, and the
  public `BearerPlug` docstring taught downstream consumers to hand-roll
  the same split. This module is the single place that knows the split
  and the re-join, so the rest of the server (and consumers) reach for
  `from_string/1` and `to_string/1` instead.

  ## Boundary contract

  `from_string/1` is the only entry point from the wire; `to_string/1`
  is the only exit point back to the wire. The two round-trip for any
  scope set whose tokens contain no spaces (the OAuth delimiter). The
  resource attribute and the JWT `scope` claim stay `String.t()` — this
  type is internal plumbing, not a wire-shape change.

  ## Ordering

  The underlying `MapSet` is unordered, so `to_string/1` does not
  produce a canonical ordering. Callers that need a stable order must
  sort the result themselves. Set-equality (`covers?/2`, `subset_of?/2`)
  is order-independent.
  """

  alias AshAuthentication.Oauth2Server.Scope

  @typedoc "A set of `Scope.t()` with set semantics for cover/subset/member checks."
  @type t :: %__MODULE__{scopes: MapSet.t(Scope.t())}

  defstruct scopes: MapSet.new()

  @doc """
  Parse a space-delimited scope string into a `ScopeSet.t()`.

  Empty / blank segments are trimmed, matching the prior
  `String.split(" ", trim: true) |> MapSet.new()` behavior. `nil` and
  `""` both yield the empty set.
  """
  @spec from_string(String.t() | nil) :: t()
  def from_string(nil), do: %__MODULE__{scopes: MapSet.new()}

  def from_string(str) when is_binary(str) do
    scopes =
      str
      |> String.split(" ", trim: true)
      |> Enum.map(&Scope.new/1)
      |> MapSet.new()

    %__MODULE__{scopes: scopes}
  end

  @doc """
  Build a `ScopeSet.t()` from an enumerable of scope-name strings — the
  shape returned by `server.scopes/0` for the configured catalogue.
  """
  @spec from_list(Enumerable.t(String.t())) :: t()
  def from_list(names) do
    scopes =
      names
      |> Enum.map(&Scope.new/1)
      |> MapSet.new()

    %__MODULE__{scopes: scopes}
  end

  @doc """
  Serialize a `ScopeSet.t()` back to the space-delimited wire string.

  Token order is not stable (see the module doc). Round-tripping a set
  whose tokens contain no spaces yields an equal value up to ordering.
  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{scopes: scopes}) do
    Enum.map_join(scopes, " ", & &1.name)
  end

  @doc """
  The scope-name strings in the set, as a list. Order is not stable.
  Used where a caller needs the wire tokens (e.g. an error message
  naming the first unknown scope).
  """
  @spec to_list(t()) :: [String.t()]
  def to_list(%__MODULE__{scopes: scopes}) do
    Enum.map(scopes, & &1.name)
  end

  @doc """
  Does `stored` cover `requested` — i.e. is every requested scope
  present in `stored`? Replaces the prior private `scope_covers?/2`.
  """
  @spec covers?(stored :: t(), requested :: t()) :: boolean()
  def covers?(%__MODULE__{scopes: stored}, %__MODULE__{scopes: requested}) do
    MapSet.subset?(requested, stored)
  end

  @doc """
  Is `requested` a subset of `allowed` — i.e. is every requested scope
  in the catalogue?
  """
  @spec subset_of?(requested :: t(), allowed :: t()) :: boolean()
  def subset_of?(%__MODULE__{scopes: requested}, %__MODULE__{scopes: allowed}) do
    MapSet.subset?(requested, allowed)
  end

  @doc """
  Is `scope` a member of the set? Accepts either a `Scope.t()` or a
  scope-name `String.t()`.
  """
  @spec member?(t(), Scope.t() | String.t()) :: boolean()
  def member?(%__MODULE__{scopes: scopes}, %Scope{name: name}),
    do: MapSet.member?(scopes, %Scope{name: name})

  def member?(%__MODULE__{scopes: scopes}, name) when is_binary(name),
    do: MapSet.member?(scopes, %Scope{name: name})
end
