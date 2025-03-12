import json
import base64
import requests


class PublicKey:
    N: int
    e: int


class SignResponse:
    signature: str
    msg: str


def get_request(url):
    session = requests.session()
    response = session.get(url)
    return json.loads(response.text)


def get_public_key() -> PublicKey:
    response = get_request(url + "/pk/")
    public_key = PublicKey()
    public_key.__dict__.update(response)
    return public_key


def sign(hexstring) -> SignResponse:
    response = get_request(url + "/sign_random_document_for_students/" + hexstring)
    sign_response = SignResponse()
    sign_response.__dict__.update(response)
    return sign_response


def get_quote(msg, signature):
    j = json.dumps({"msg": msg, "signature": signature})
    base64_data = base64.b64encode(j.encode()).decode()

    session = requests.session()
    session.cookies.set("grade", base64_data)
    r = session.get(url + "/quote")

    return r


if __name__ == "__main__":

    url = "https://rsasig.syssec.dk"

    public_key = get_public_key()

    message = "You got a 12 because you are an excellent student! :)"
    message_hex = message.encode("utf-8").hex()
    message_bytes = bytes.fromhex(message_hex)
    message_int = int.from_bytes(message_bytes, byteorder="big")
    # print(message_int)

    message_1 = 5
    message_1_sign = sign(f"{message_1:02x}")
    signature_1 = int(message_1_sign.signature, 16)

    message_2 = message_int // 5 % public_key.N
    message_2_sign = sign(f"{message_2:02x}")
    signature_2 = int(message_2_sign.signature, 16)

    signature = signature_1 * signature_2 % public_key.N
    quote = get_quote(message.encode("utf-8").hex(), f"{signature:02x}")

    print(quote.text)
