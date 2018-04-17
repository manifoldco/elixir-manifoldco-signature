defmodule ManifoldcoSignature.Signature do
  @moduledoc """
  Verifies a request signature for the Manifold.co service callbacks.

  https://docs.manifold.co/providers#section/Authentication
  """

  #
  # typespecs (signature)
  #

  @typedoc """
  Endorsement provided as the 3 argument in the `x-signature` header.
  """
  @type endorsement :: binary

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
  @signature_delimiter " "
  @signature_header_key "x-signature"

  #
  # API
  #

  @doc """
  Signs the request returning back the new headers.

  Unless you are Manfiold this function should be used for testing purposes.
  """
  @spec sign(
          ManifoldcoSignature.request_method(),
          ManifoldcoSignature.request_path(),
          ManifoldcoSignature.request_query_string(),
          ManifoldcoSignature.request_headers(),
          ManifoldcoSignature.request_body(),
          ManifoldcoSignature.master_key(),
          Keyword.t()
        ) ::
          {:ok, ManifoldcoSignature.request_headers()}
          | {:error, ManifoldcoSignature.error_reason()}
  def sign(method, path, query_string, headers, body, master_key, _opts \\ []) do
    now = DateTime.utc_now()
    {:ok, date} = Timex.format(now, @date_format)
    headers = headers ++ [{"date", date}]
    %{public: master_public_key, secret: master_secret_key} = :enacl.box_keypair()
    header_keys = Enum.map(headers, fn {key, _val} -> key end)
    canonized_message = canonize(method, path, query_string, header_keys, headers, body)

    with {:ok, endorsement} <- :enacl.sign(master_public_key, master_secret_key),
         {:ok, signature} <- :enacl.sign(canonized_message, master_public_key) do
      encoded_public_key = Base.url_encode64(master_public_key)
      encoded_endorsement = Base.url_encode64(endorsement)
      encoded_signature = Base.url_encode64(signature)

      signature =
        Enum.join(
          [encoded_signature, encoded_public_key, encoded_endorsement],
          @signature_delimiter
        )

      header_keys =
        headers
        |> Enum.map(fn {key, _val} -> key end)
        |> Enum.join(@signed_headers_delimiter)

      headers =
        headers ++
          [
            {@signed_headers_key, header_keys},
            {@signature_header_key, signature}
          ]

      {:ok, headers}
    else
      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Validates the request via the x-signature header.
  """
  @spec validate(
          ManifoldcoSignature.request_method(),
          ManifoldcoSignature.request_path(),
          ManifoldcoSignature.request_query_string(),
          ManifoldcoSignature.request_headers(),
          ManifoldcoSignature.request_body(),
          ManifoldcoSignature.master_key(),
          Keyword.t()
        ) ::
          :ok
          | {:error, ManifoldcoSignature.error_reason()}
  def validate(method, path, query_string, headers, body, master_key, opts \\ []) do
    with {:ok, signed_headers_value} <- fetch_first_header_value(headers, @signed_headers_key),
         signed_headers <- parse_signed_headers(signed_headers_value),
         canonized_message <- canonize(method, path, query_string, signed_headers, headers, body),
         {:ok, date_header} <- fetch_first_header_value(headers, @date_header_key),
         {:ok, date} <- parse_date(date_header),
         {:ok, signature_header} <- fetch_first_header_value(headers, @signature_header_key),
         {:ok, {signature, public_key, endorsement}} <- parse_signature(signature_header),
         :ok <- validate_not_expired(date, opts),
         {:ok, _message} <- :enacl.sign_verify_detached(endorsement, public_key, master_key),
         {:ok, _message} <-
           :enacl.sign_verify_detached(
             signature,
             canonized_message,
             public_key
           ) do
      :ok
    else
      false ->
        reason = "Signature is invalid"
        {:error, reason}
    end
  end

  #
  # Util (sorted alphabetically)
  #

  defp canonize(method, path, query_string, signed_headers, headers, body) do
    canonized_method = canonize_method(method)
    canonized_query_string = canonize_query_string(query_string)
    canonized_headers = canonize_headers(headers, signed_headers)

    "#{canonized_method} #{path}#{canonized_query_string}#{@new_line}" <>
      "#{canonized_headers}#{@new_line}" <> "#{body}"
  end

  # Builds a canonical version of the headers as described by Manifold.
  @spec canonize_headers(ManifoldcoSignature.request_headers(), [binary]) :: canonized_headers
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
  @spec canonize_method(ManifoldcoSignature.request_method()) :: canonized_method
  defp canonize_method(method) do
    String.downcase(method)
  end

  # Normalizes a query string as described in the Manifold docs by splitting each parameter,
  # sorting them, and then joining them back into a proper query string.
  @spec canonize_query_string(ManifoldcoSignature.request_query_string()) ::
          canonized_query_string
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
  @spec fetch_first_header_value(
          ManifoldcoSignature.request_headers(),
          ManifoldcoSignature.request_header_key()
        ) ::
          {:ok, ManifoldcoSignature.request_header_value()}
          | {:error, ManifoldcoSignature.error_reason()}
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
  @spec get_req_header(
          ManifoldcoSignature.request_headers(),
          ManifoldcoSignature.request_header_key()
        ) :: [ManifoldcoSignature.request_header_value()]
  defp get_req_header(headers, key) when is_binary(key) do
    for {k, v} <- headers, k == key, do: v
  end

  # Parses the signed headers valued provided in the `x-signed-headers` header.
  @spec parse_signed_headers(ManifoldcoSignature.request_header_value()) :: [binary]
  defp parse_signed_headers(signed_headers) do
    String.split(signed_headers, @signed_headers_delimiter)
  end

  # Parses a RFC3339 formatted date into a proper `DateTime.t`
  @spec parse_date(ManifoldcoSignature.request_header_value()) ::
          {:ok, DateTime.t()}
          | {:error, ManifoldcoSignature.error_reason()}
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
  @spec parse_signature(ManifoldcoSignature.request_header_value()) ::
          {:ok, {signature, public_key, endorsement}}
          | {:error, ManifoldcoSignature.error_reason()}
  defp parse_signature(signature) do
    with [signature_raw, public_key_raw, endorsement_raw] <-
           String.split(signature, @signature_delimiter),
         {:ok, signature} <- Base.url_decode64(signature_raw, padding: false),
         {:ok, public_key} <- Base.url_decode64(public_key_raw, padding: false),
         {:ok, endorsement} <- Base.url_decode64(endorsement_raw, padding: false) do
      {:ok, {signature, public_key, endorsement}}
    else
      _other ->
        message = "Signature header malformed"

        {:error, message}
    end
  end

  # Validates that the request date has not expired with an allowed drift
  # as defined by `@allowed_time_drift_seconds`.
  @spec validate_not_expired(DateTime.t(), Keyword.t()) ::
          :ok
          | {:error, ManifoldcoSignature.error_reason()}
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
