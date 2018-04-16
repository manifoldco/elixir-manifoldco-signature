defmodule ManifoldcoSignature.MixProject do
  use Mix.Project

  def project do
    [
      app: :manifoldco_signature,
      version: "0.0.1",
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:certifi, "2.0.0"},
      {:timex, "~> 3.2.1"},
      {:enacl, github: "jlouis/enacl", ref: "c8403ab198b80863479c2ab5a9ccd0a8d73a57c4"}
    ]
  end
end
