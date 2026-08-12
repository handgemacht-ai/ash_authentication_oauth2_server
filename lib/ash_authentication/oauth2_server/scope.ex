# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Scope do
  @moduledoc """
  A single OAuth scope token.

  OAuth 2.1 carries scopes as a space-delimited string at every protocol
  boundary (the `scope` authorize parameter, the `scope` JWT claim, the
  `scope` token-response field). Each whitespace-delimited token is one
  scope; this struct names that token so set operations stay typed
  instead of operating on bare strings.

  Scope tokens never contain spaces (space is the delimiter), so the
  `name` is the exact wire token — no normalization, no quoting.
  """

  @typedoc "A single scope token, e.g. `\"mcp.read\"`."
  @type t :: %__MODULE__{name: String.t()}

  defstruct [:name]

  @doc "Wrap a scope-name string as a `Scope.t()`."
  @spec new(String.t()) :: t()
  def new(name) when is_binary(name), do: %__MODULE__{name: name}
end
