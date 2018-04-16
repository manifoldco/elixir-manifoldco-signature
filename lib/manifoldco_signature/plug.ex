# defmodule ManifoldcoSignature.Plug do
#   @moduledoc """
#   Plug that authenicates requests from the Manifold.co service.
#   """

#   alias ManifoldcoSignature.Signature

#   require Logger

#   @behaviour Plug

#   def init(_opts) do
#     []
#   end

#   def call(conn, _opts) do
#     conn = Plug.Conn.fetch_query_params(conn)
#     method = conn.method
#     request_path = conn.request_path
#     query_string = conn.query_string
#     headers = Enum.into(conn.headers, %{})

#     with {:ok, signature} <- Signature.build(method, request_path, query_string, headers, body),
#          :ok <- Signature.verify(signature)
#     do
#       conn
#     else
#       {:error, reason} ->
#         Logger.info fn ->
#           "Manifold authentication failed: #{reason}"
#         end

#         conn
#         |> Plug.Conn.send_resp(:unauthorized, "")
#         |> Plug.Conn.halt()
#     end
#   end
# end
