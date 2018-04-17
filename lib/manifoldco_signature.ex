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
          master_key
        ) ::
          :ok
          | {:error, error_reason}
  def verify(method, path, query_string, headers, body, master_key) do
    with {:ok, signature} <- Signature.build(method, path, query_string, headers, body),
         :ok <- Signature.validate(signature, master_key) do
      :ok
    else
      {:error, _reason} = error_tuple ->
        error_tuple
    end
  end
end
