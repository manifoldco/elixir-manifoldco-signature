defmodule ManifoldcoSignature do
  @moduledoc """
  Verifies incoming provider callback requests from the Manifold.co service.

  https://docs.manifold.co/providers#section/Authentication
  """

  alias __MODULE__.Signature

  #
  # typespecs
  #

  @typedoc """
  User friendly error reason.
  """
  @type error_reason :: binary

  @typedoc """
  Master key provided by Manifold. This should be securely stored in your environment and
  passed to `validate/6` as the last argument.
  """
  @type master_key :: binary

  @typedoc """
  The raw request body.
  """
  @type request_body :: nil | binary

  @type request_header_key :: binary
  @type request_header_value :: binary

  @typedoc """
  Tuple form of the request headers, the default structure provided from `Plug.Conn.headers`.
  """
  @type request_headers :: [{request_header_key, request_header_value}]

  @typedoc """
  String representation of the method, case insensitive. This library will normalize the
  case as described in the Manifold docs.
  """
  @type request_method :: binary

  @typedoc """
  The raw request path with a leading /.
  """
  @type request_path :: binary

  @typedoc """
  String representation of the URL query string (without the ?). This library will normalize
  the order of the parameters as described in the Manifold documentation.
  """
  @type request_query_string :: nil | binary

  @typedoc """
  Option that can be passed to `verify/6`.
  """
  @type verify_opt :: {:master_key, master_key}

  #
  # Module vars
  #

  @base64_encoded_master_key "PtISNzqQmQPBxNlUw3CdxsWczXbIwyExxlkRqZ7E690"

  #
  # API
  #

  @doc """
  Verifies the request. Each request part is required to build the canoncical form of the
  request and the `master_key` should be securetly stored in your environment and passed
  as the last argument. The `master_key` is provided by Manifold.
  """
  @spec verify(
          request_method,
          request_path,
          request_query_string,
          request_headers,
          request_body,
          [verify_opt]
        ) ::
          :ok
          | {:error, error_reason}
  def verify(method, path, query_string, headers, body, opts \\ []) do
    {master_key, opts} =
      Keyword.pop_lazy(opts, :master_key, fn ->
        {:ok, master_key} = Base.decode64(@base64_encoded_master_key, padding: false)
        master_key
      end)

    case Signature.verify(method, path, query_string, headers, body, master_key, opts) do
      :ok ->
        :ok

      {:error, _reason} = error_tuple ->
        error_tuple
    end
  end
end
