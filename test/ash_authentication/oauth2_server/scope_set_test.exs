# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ScopeSetTest do
  @moduledoc """
  Pins the behavior of `ScopeSet` — the value object that replaces the
  space-delimited scope string re-parsed into a `MapSet` at every site.
  """
  use ExUnit.Case, async: true

  alias AshAuthentication.Oauth2Server.{Scope, ScopeSet}

  describe "from_string/1" do
    test "splits on spaces and trims blanks (mirrors the old split+trim)" do
      assert ScopeSet.from_string("mcp admin") |> ScopeSet.to_list() |> Enum.sort() ==
               ["admin", "mcp"]

      assert ScopeSet.from_string("  mcp   admin  ") |> ScopeSet.to_list() |> Enum.sort() ==
               ["admin", "mcp"]
    end

    test "nil and empty string yield the empty set" do
      assert ScopeSet.from_string(nil) == %ScopeSet{scopes: MapSet.new()}
      assert ScopeSet.from_string("") == %ScopeSet{scopes: MapSet.new()}
    end

    test "a single scope yields a one-element set" do
      assert ScopeSet.from_string("mcp") |> ScopeSet.to_list() == ["mcp"]
    end
  end

  describe "from_list/1" do
    test "builds a set from the server-catalogue shape" do
      set = ScopeSet.from_list(["mcp", "admin"])
      assert ScopeSet.member?(set, "mcp")
      assert ScopeSet.member?(set, "admin")
      refute ScopeSet.member?(set, "other")
    end
  end

  describe "to_string/1" do
    test "round-trips a set whose tokens contain no spaces" do
      original = "mcp admin read write"

      names =
        ScopeSet.from_string(original) |> ScopeSet.to_string() |> String.split(" ") |> Enum.sort()

      assert names == Enum.sort(String.split(original, " ", trim: true))
    end

    test "empty set serializes to the empty string" do
      assert ScopeSet.to_string(ScopeSet.from_string("")) == ""
    end
  end

  describe "covers?/2" do
    test "true when stored is a superset of requested" do
      stored = ScopeSet.from_string("mcp admin")
      requested = ScopeSet.from_string("mcp")
      assert ScopeSet.covers?(stored, requested)
    end

    test "false when requested has a scope not in stored" do
      stored = ScopeSet.from_string("mcp")
      requested = ScopeSet.from_string("mcp admin")
      refute ScopeSet.covers?(stored, requested)
    end

    test "true when both are empty" do
      assert ScopeSet.covers?(ScopeSet.from_string(""), ScopeSet.from_string(""))
    end

    test "true when requested is empty" do
      assert ScopeSet.covers?(ScopeSet.from_string("mcp"), ScopeSet.from_string(""))
    end
  end

  describe "subset_of?/2" do
    test "true when requested is fully inside allowed" do
      assert ScopeSet.subset_of?(
               ScopeSet.from_string("mcp"),
               ScopeSet.from_list(["mcp", "admin"])
             )
    end

    test "false when requested exceeds allowed" do
      refute ScopeSet.subset_of?(ScopeSet.from_string("mcp admin"), ScopeSet.from_list(["mcp"]))
    end
  end

  describe "member?/2" do
    test "accepts a name string" do
      set = ScopeSet.from_string("mcp admin")
      assert ScopeSet.member?(set, "mcp")
      refute ScopeSet.member?(set, "other")
    end

    test "accepts a Scope.t()" do
      set = ScopeSet.from_string("mcp admin")
      assert ScopeSet.member?(set, Scope.new("admin"))
      refute ScopeSet.member?(set, Scope.new("other"))
    end
  end
end
