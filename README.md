# ManifoldcoSignature

Verify signed HTTP requests from Manifold.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `manifoldco_signature` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:manifoldco_signature, "~> 0.0.1"}
  ]
end
```

Please note that this library uses a specific version of the
[enacl](https://github.com/jlouis/enacl) library. This is due to broken build requirements
when trying to compile the libsodium bindings.

Oh, and you'll need `libsodium` to be installed on the host machine. If you're on mac you
can do so via:

```
brew install libsodium
```

## Documentation

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/manifoldco_signature](https://hexdocs.pm/manifoldco_signature).

## Credit

This package was built by

[![timber.io](http://res.cloudinary.com/timber/image/upload/v1490197244/pricing/logo-purple.png)](http://timber.io/)