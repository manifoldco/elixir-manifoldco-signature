defmodule ManifoldcoSignature.Signature do
  @moduledoc """
  Verifies a request signature for the Manifold.co service callbacks.

  https://docs.manifold.co/providers#section/Authentication
  """

  @all_keys [:date, :endorsement, :public_key, :signature, :message]
  @enforce_keys @all_keys
  defstruct @all_keys

  #
  # typespecs (signature)
  #

  @type t :: %__MODULE__{
          date: DateTime.t(),
          endorsement: endorsement,
          public_key: public_key,
          signature: signature,
          message: message
        }

  @typedoc """
  Endorsement provided as the 3 argument in the `x-signature` header.
  """
  @type endorsement :: binary

  @typedoc """
  User friendly error reason.
  """
  @type error_reason :: binary

  @typedoc """
  Master key provided by Manifold. This should be securely stored in your environment and
  passed to `validate/2`.
  """
  @type master_key :: binary

  @typedoc """
  The canonized request message to verify.
  """
  @type message :: binary

  @typedoc """
  Public key provided as the second argument in the `x-signature` header.
  """
  @type public_key :: binary

  @typedoc """
  Request signature provied as the first argument in the `x-signature` header.
  """
  @type signature :: binary

  #
  # typespecs (canonizing)
  #

  @type canonized_headers :: binary
  @type canonized_method :: binary
  @type canonized_query_string :: binary
  @type request_body :: nil | binary
  @type request_header_key :: binary
  @type request_header_value :: binary
  @type request_headers :: [{request_header_key, request_header_value}]
  @type request_method :: binary
  @type request_path :: binary
  @type request_query_string :: nil | binary

  #
  # module vars
  #

  @allowed_time_drift_seconds 60 * 5
  @date_format "{RFC3339}"
  @date_header_key "date"
  @new_line "\n"
  @query_string_delimiter "&"
  @signed_headers_delimiter " "
  @signed_headers_key "x-signed-headers"
  @signed_headers_value_delimiter ","
  @signature_header_key "x-signature"

  #
  # API
  #

  @doc """
  Builds a new signature from the provided request data.
  """
  @spec build(
          request_method,
          request_path,
          request_query_string,
          request_headers,
          request_body
        ) ::
          {:ok, t}
          | {:error, error_reason}
  def build(method, path, query_string, headers, body) do
    with canonized_method <- canonize_method(method),
         canonized_query_string <- canonize_query_string(query_string),
         {:ok, signed_headers_header} <- fetch_first_header_value(headers, @signed_headers_key),
         signed_headers <- parse_signed_headers(signed_headers_header),
         canonized_headers <- canonize_headers(headers, signed_headers),
         {:ok, date_header} <- fetch_first_header_value(headers, @date_header_key),
         {:ok, date} <- parse_date(date_header),
         {:ok, signature_header} <- fetch_first_header_value(headers, @signature_header_key),
         {:ok, {signature, public_key, endorsement}} <- parse_signature(signature_header) do
      message =
        "#{canonized_method} #{path}#{canonized_query_string}#{@new_line}" <>
          "#{canonized_headers}#{@new_line}" <> "#{body}"

      raise message

      signature_struct = %__MODULE__{
        date: date,
        endorsement: endorsement,
        public_key: public_key,
        signature: signature,
        message: message
      }

      {:ok, signature_struct}
    else
      {:error, _reason} = error_tuple ->
        error_tuple
    end
  end

  @doc """
  Validates the signature (`t`) against the `master_key`.
  """
  @spec validate(t, master_key, Keyword.t()) ::
          :ok
          | {:error, error_reason}
  def validate(signature, master_key, opts \\ []) do
    with :ok <- validate_not_expired(signature.date, opts),
         true <-
           Ed25519.valid_signature?(signature.public_key, signature.endorsement, master_key),
         true <-
           Ed25519.valid_signature?(signature.message, signature.signature, signature.public_key) do
    else
      false ->
        reason = "Signature is invalid"
        {:error, reason}
    end
  end

  #
  # Util (sorted alphabetically)
  #

  # Builds a canonical version of the headers as described by Manifold.
  @spec canonize_headers(request_headers, [binary]) :: canonized_headers
  defp canonize_headers(headers, signed_headers) do
    signed_headers
    |> Enum.concat([@signed_headers_key])
    |> Enum.map(fn key ->
      values =
        headers
        |> get_req_header(key)
        |> Enum.join(@signed_headers_value_delimiter)

      "#{key}: #{values}"
    end)
    |> Enum.join(@new_line)
  end

  # Normalizes a request method as described in the Manifold docs by downcases the method.
  @spec canonize_method(request_method) :: canonized_method
  defp canonize_method(method) do
    String.downcase(method)
  end

  # Normalizes a query string as described in the Manifold docs by splitting each parameter,
  # sorting them, and then joining them back into a proper query string.
  @spec canonize_query_string(request_query_string) :: canonized_query_string
  defp canonize_query_string(nil), do: nil

  defp canonize_query_string(query_string) do
    canonized_query_string =
      query_string
      |> String.split(@query_string_delimiter)
      |> Enum.sort()
      |> Enum.join(@query_string_delimiter)

    "?#{canonized_query_string}"
  end

  # Headers should not have more than one value in the context of Manifold.
  @spec fetch_first_header_value(request_headers, request_header_key) ::
          {:ok, request_header_value}
          | {:error, error_reason}
  defp fetch_first_header_value(headers, key) do
    case get_req_header(headers, key) do
      [value | _] ->
        {:ok, value}

      _else ->
        reason = "#{key} not present"
        {:error, reason}
    end
  end

  # Returns the values of the request header specified by `key`.
  @spec get_req_header(request_headers, request_header_key) :: [request_header_value]
  defp get_req_header(headers, key) when is_binary(key) do
    for {k, v} <- headers, k == key, do: v
  end

  # Parses the signed headers valued provided in the `x-signed-headers` header.
  @spec parse_signed_headers(request_header_value) :: [binary]
  defp parse_signed_headers(signed_headers) do
    String.split(signed_headers, @signed_headers_delimiter)
  end

  # Parses a RFC3339 formatted date into a proper `DateTime.t`
  @spec parse_date(request_header_value) ::
          {:ok, DateTime.t()}
          | {:error, error_reason}
  defp parse_date(date_time_string) do
    case Timex.parse(date_time_string, @date_format) do
      {:ok, result} ->
        date_time = Timex.to_datetime(result)
        {:ok, date_time}

      {:error, _reason} = error_tuple ->
        error_tuple
    end
  end

  # Parses the Manifold provided signature from the `x-signature` header into
  # 3 base 64 decoded parts.
  @spec parse_signature(request_header_value) ::
          {:ok, {signature, public_key, endorsement}}
          | {:error, error_reason}
  defp parse_signature(signature) do
    case String.split(signature, " ") do
      [signature_raw, public_key_raw, endorsement_raw] ->
        signature = Base.url_decode64(signature_raw)
        public_key = Base.url_decode64(public_key_raw)
        endorsement = Base.url_decode64(endorsement_raw)

        {:ok, {signature, public_key, endorsement}}

      _other ->
        message = "Signature header malformed"
        {:error, message}
    end
  end

  # Validates that the request date has not expired with an allowed drift
  # as defined by `@allowed_time_drift_seconds`.
  @spec validate_not_expired(DateTime.t(), Keyword.t()) ::
          :ok
          | {:error, error_reason}
  defp validate_not_expired(date, opts) do
    unix = DateTime.to_unix(date, :seconds)
    now = Keyword.get(opts, :now, DateTime.utc_now())
    now_unix = now |> DateTime.to_unix(:seconds)

    if unix >= now_unix - @allowed_time_drift_seconds do
      :ok
    else
      reason = "Request has expired via the Date header"
      {:error, reason}
    end
  end
end
