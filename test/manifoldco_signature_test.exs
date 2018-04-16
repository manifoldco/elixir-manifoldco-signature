defmodule ManifoldcoSignatureTest do
  use ManifoldcoSignature.TestCase
  doctest ManifoldcoSignature

  @raw_master_key "PY7wu3q3-adYr9-0ES6CMRixup9OjO5iL7EFDFpolhk"

  describe "ManifoldcoSignature.validate/2" do
    test "success" do
      method = "PUT"
      path = "/v1/resources/2686c96868emyj61cgt2ma7vdntg4"
      query_string = nil

      headers = [
        {"date", "2017-03-05T23:53:08Z"},
        {"host", "127.0.0.1:4567"},
        {"content-type", "application/json"},
        {"content-length", "143"},
        {"x-signed-headers", "host date content-type content-length"},
        {"x-signature",
         "Nb9iJZVDFrcf8-dw7AsuSCPtdoxoAr61YVWQe-5b9z_YiuQW73wR7RRsDBPnrBMtXIg_h8yKWsr-ZNRgYbM7CA FzNbTkRjAGjkpwHUbAhjvLsIlAlL_M6EUh5E9OVEwXs qGR6iozBfLUCHbRywz1mHDdGYeqZ0JEcseV4KcwjEVeZtQN54odcJ1_QyZkmHacbQeHEai2-Aw9EF8-Ceh09Cg"}
      ]

      body =
        "{\"id\":\"2686c96868emyj61cgt2ma7vdntg4\",\"plan\":\"low\",\"product\":\"generators\",\"region\":\"aws::us-east-1\",\"user_id\":\"200e7aeg2kf2d6nud8jran3zxnz5j\"}\n"

      {:ok, back_then, _offset} = DateTime.from_iso8601("2017-03-05T23:53:08Z")

      {:ok, signature} =
        ManifoldcoSignature.Signature.build(method, path, query_string, headers, body)

      {:ok, master_key} = Base.url_decode64(@raw_master_key, padding: false)

      assert :ok =
               ManifoldcoSignature.Signature.validate(
                 signature,
                 master_key,
                 now: back_then
               )
    end
  end
end
