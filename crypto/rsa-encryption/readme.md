# RSA Encryption

### Task 5: Exploiting Encryption Oracles

You are given the source code of a simple website that distributed quotes.
However, you only receive a quote if you can present a cookie containing a
valid authentication token. Such a token is an RSA encryption of a certain
message, according to the PKS 1.5 standard.

You first need to recover the secret part of the message, and then create a valid
ciphertext containing the right plaintext without having access to the
private key for decryption.

This requires you to exploit the properties of RSA encryption with an insecure
padding mode, together with the fact that the service is faulty and outputs
weird error messages depending on the parity of the plaintext.

To get started with the task, you can host a local version on your own machine (see below) and use it as training ground.
Afterwards, you can attack a version of the website hosted [here](https://rsaenc.syssec.dk).

NB: This is obviously not a good authentication method, but rather a somewhat
artificial example demonstrating the problems of weak padding schemes.

### Task 6: Implementing RSA-OEAP

Textbook RSA encryption is not secure. An attacker is able to obtain
ciphertexts for messages that were never encrypted as such.
To prevent such attacks, padding schemes can be used. One such scheme is
standardized as PKCS 1.5, but it suffers from parity and padding oracles in
case the plaintext is not handled properly. A more secure alternative is
OAEP (Optimal Asymmetric Encryption Padding).

The part of the assignment requires the implementation of the RSA-OAEP according
to [RFC8017](https://datatracker.ietf.org/doc/html/rfc8017#section-7.1) using
SHA-256 as hash and mask generation function and an empty label string.

The objective of this assignment is to implement support for the key generation,
encryption and decryption operations, such that the resulting
cryptosystem is consistent and able to decrypt its own ciphertexts.

In your implementation, you should target a security level of 128 bits, i.e.,
use RSA moduli of size 3072 bits.  You are allowed to use library functions
such as random number generators and mathematical subroutines (of course you
cannot just wrap an existing library for RSA), but you need to document and
justify you decisions with respect to security.  Especially, be careful when
selecting the random number generator for key generation, as to avoid the
pitfalls discussed in class. If encoding/decoding presents a challenge, you
can reuse existing code as well, or read the [IEEE P1363 specification](https://web.archive.org/web/20170810025803/http://grouper.ieee.org/groups/1363/P1363a/contributions/pss-submission.pdf) for reference.
For reference, the Wikipedia has some [good pictures](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding) of the RSA-OAEP encoding/decoding functions.

Any high-level programming language will suffice. Immediate suggestions are
Python, for its native support for arbitrary-precision integers, byte strings,
and its extensive standard library; Java, due to its library support for
multi-precision integers; or the combination of the C programming language with
the GMP library.

## Running the Service Locally

With the given files, you can play around with the service and test your code
locally on your own computer.  Note that all secret data has been redacted from
the code and replaced with dummy values.

If you have installed Python 3, you can install the required packages in an
isolated virtual environment:
```
$ python -m venv venv               # (1) create a virtual environment in the directory `venv`
$ . ./venv/bin/activate             # (2) activate the virtual environment
$ pip install -r requirements.txt   # (3) install the required packages into the virtual environment
```
To run the service you then simply execute the following:
```
$ FLASK_APP=main flask run          # (4) run the application
```
The next time you want to run the service, you only need to repeat step (4)
(possibly after activating the virtual environment again Step (4)).

Alternatively, we also prepared a Docker container that you can use:
```
# docker build -t rsa-encryption .
# docker run -p 5000:80 rsa-encryption
```

In both cases, the application is reachable at <http://localhost:5000/>.
