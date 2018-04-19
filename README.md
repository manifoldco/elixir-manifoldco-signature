# ManifoldcoSignature

Verify signed HTTP requests from Manifold.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `manifoldco_signature` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    # Required for the `manifoldco_signature` dependency.
    {:enacl, github: "jlouis/enacl", ref: "c8403ab198b80863479c2ab5a9ccd0a8d73a57c4"}
    {:manifoldco_signature, "~> 0.0.1"}
  ]
end
```

Note that this library uses a specific version of the
[enacl](https://github.com/jlouis/enacl) library. This is due to broken build requirements
when trying to compile the `libsodium` bindings.

Oh, and you'll need `libsodium` to be installed on the host machine. If you're on mac you
can do so via:

```
brew install libsodium
```

## Documentation

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/manifoldco_signature](https://hexdocs.pm/manifoldco_signature).

## Using with Plug

This library does not include `Plug` as a dependency but instead takes the raw request arguments
so that you can use your framework of choise. Since `Plug` is popular below is a plug that
works with this library:

```elixir
defmodule ManifoldAuthorization do
  @moduledoc """
  Plug that authenicates requests from the Manifold.co service.
  """

  alias ManifoldcoSignature

  require Logger

  @behaviour Plug

  #
  # Callbacks
  #

  def init(_opts) do
    []
  end

  def call(conn, _opts) do
    conn = Plug.Conn.fetch_query_params(conn)
    method = conn.method
    request_path = conn.request_path
    query_string = conn.query_string
    headers = conn.req_headers

    with {:ok, body, conn} <- Plug.Conn.read_body(conn),
         :ok <- ManifoldcoSignature.verify(method, request_path, query_string, headers, body),
         # We must parse the body here because `Plug.Conn.read_body/1` can only be called once.
         # Once called the body is no longer available.
         {:ok, body_params} <- Poison.decode(body) do
      Map.put(conn, :body_params, body_params)
    else
      {:error, reason} ->
        Logger.info(fn ->
          "Manifold authentication failed: #{inspect(reason)}"
        end)

        conn
        |> Plug.Conn.send_resp(:unauthorized, "")
        |> Plug.Conn.halt()
    end
  end
end
```

**Warning**

You must remove the `Plug.Parsers` plug in your `endpoint.ex` file since it reads the body,
this makes it impossibel for the above manifold plug to read the body also.

## Credit

This package was built by

[![timber.io](http://res.cloudinary.com/timber/image/upload/v1490197244/pricing/logo-purple.png)](http://timber.io/)

A Manifold logging provider.