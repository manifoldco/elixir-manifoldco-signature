defmodule ManifoldcoSignature.MixProject do
  use Mix.Project

  @project_description """
  Verifies incoming Manifold.co provider callback requests.
  """

  @source_url "https://github.com/timberio/elixir-manifoldco-signature"
  @homepage_url "https://github.com/timberio/elixir-manifoldco-signature"
  @version "1.0.0"

  def project do
    [
      app: :manifoldco_signature,
      name: "Manifold Signature",
      version: @version,
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env()),
      description: @project_description,
      source_url: @source_url,
      homepage_url: @homepage_url,
      package: package(),
      deps: deps(),
      docs: docs(),
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod
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

  # Package options for the Hex package listing
  #
  # See `mix help hex.publish` for more information about
  # the options used in this section
  defp package() do
    [
      name: :manifoldco_signature,
      files: ["lib", "mix.exs", "README*", "LICENSE*"],
      maintainers: ["Ben Johnson"],
      licenses: ["BD3"],
      links: %{
        "GitHub" => @source_url
      }
    ]
  end

  # Documentation options for ExDoc
  defp docs() do
    [
      source_ref: "v#{@version}",
      main: "readme",
      extras: [
        "README.md": [title: "README"],
        "LICENSE.md": [title: "LICENSE"]
      ]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:earmark, "~> 1.2", only: [:dev, :docs]},
      {:ex_doc, "~> 0.15", only: [:dev, :docs]},
      {:enacl,
       github: "jlouis/enacl", ref: "c8403ab198b80863479c2ab5a9ccd0a8d73a57c4", only: :test},
      {:timex, "~> 3.2.1"}
    ]
  end
end
