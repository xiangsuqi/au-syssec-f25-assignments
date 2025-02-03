import json
import secrets
from flask import Flask, request, make_response, redirect, url_for
from secret_data import rsa_key, secret
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes


app = Flask(__name__)
quotes = open('quotes.txt', 'r').readlines()

# PKCS#1 v1.5 Padding
def pkcs1_pad(message, block_size):
    """Pads message using PKCS#1 v1.5 scheme."""
    if len(message) > block_size - 11:
        raise ValueError("Message too long for RSA block size")
    padding_length = block_size - len(message) - 3
    padding = secrets.token_bytes(padding_length).replace(b"\x00", b"\x01")  # Avoid null bytes
    return b"\x00\x02" + padding + b"\x00" + message

def pkcs1_unpad(padded_message, block_size):
    if len(padded_message) != block_size:
        return None  # Invalid length

    if padded_message[0] != 0x00 or padded_message[1] != 0x02:
        return None  # Invalid padding format

    # Find the 0x00 separator (must be after padding)
    separator_index = padded_message.find(0x00, 2)
    if separator_index == -1:
        return None  # No separator found, invalid padding

    # Extract the actual message (everything after the 0x00 separator)
    return padded_message[separator_index + 1:]

def encrypt(message: bytes) -> bytes:
    # modulus and private exponent
    N = rsa_key['_n']
    e = rsa_key['_e']
    """Encrypts message with PKCS#1 v1.5 padding."""
    block_size = (N.bit_length() + 7) // 8
    padded_message = pkcs1_pad(message, block_size)
    m = bytes_to_long(padded_message)
    # compute the ciphertext
    c = pow(m, e, N)
    # encode the ciphertext into a bytes using big-endian byte order
    ciphertext = c.to_bytes(block_size, 'big')
    return ciphertext

def decrypt(ciphertext: bytes) -> bytes:
    """Decrypt a ciphertext using our private key."""
    # modulus and private exponent
    N = rsa_key['_n']
    d = rsa_key['_d']
    # interpret the bytes of the ciphertext as an integer stored in big-endian
    # byte order
    c = bytes_to_long(ciphertext)
    # decrypt the ciphertext
    m = pow(c, d, N)
    if not 0 <= m < N:
        raise ValueError('message too large')
    block_size = (N.bit_length() + 7) // 8
    m_bytes = long_to_bytes(m, block_size)
    # Check padding
    return pkcs1_unpad(m_bytes, block_size)

def check(ciphertext: bytes) -> bytes:
    """Decrypt a ciphertext using our private key."""
    # modulus and private exponent
    N = rsa_key['_n']
    d = rsa_key['_d']
    # interpret the bytes of the ciphertext as an integer stored in big-endian
    # byte order
    c = bytes_to_long(ciphertext)
    # decrypt the ciphertext
    m = pow(c, d, N)
    if not 0 <= m < N:
        raise ValueError('message too large')
    return m % 2

@app.route('/pk/')
def pk():
    """Publish our public key as JSON."""
    N = int(rsa_key['_n'])
    e = int(rsa_key['_e'])
    return {'N': N, 'e': e}

@app.route('/')
def index():
    """Landing page, hand out authentication tokens."""
    # create a response object
    response = make_response('<p>Here, have a cookie!</p>')
    # totally secure way to create an authentication token:

    # - create a secret plaintext (NB: `{secret}` is substituted for a secret
    # string, which you need to recover)
    plaintext = f'You never figure out that "{secret}". :)'.encode()
    # - encrypt this plaintext
    token = encrypt(plaintext)
    # - store the ciphertext hex-encoded in a cookie
    response.set_cookie('authtoken', token.hex())
    return response


@app.route('/quote/')
def quote():
    """Show quotes to the right users."""
    # check if an authentication token is there
    token = request.cookies.get('authtoken')
    if token is None:
        return redirect(url_for('index'))
    try:
        # try to decode/decrypt the token
        token = bytes.fromhex(token)
        if (check(token) == 0):
            return "I do not like even numbers."
    except Exception as e:
        return str(e)
    # check if this token is valid
    plain = decrypt(token)
    if plain != None and plain.decode() == secret + " because of weird oracles!":
        return f'<quote>\n{secrets.choice(quotes)}</quote>'
    else:
        return 'No quote for you!'
