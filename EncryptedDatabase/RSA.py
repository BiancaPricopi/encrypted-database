import os
import random as rand
import sys

from Crypto.Util import number


def get_prime_of_length(length):
    return number.getPrime(length)


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def gcd_extended(a, b):
    # return (g, x, y) a.i. a*x + b*y = g = gcd(a, b)
    old_s, s = 1, 0
    old_t, t = 0, 1
    while b != 0:
        (quotient, b), a = divmod(a, b), b
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return a, old_s, old_t


def multiplicative_inverses(a, b):
    _, x, _ = gcd_extended(a, b)
    return x % b


def generate_e(phi):
    return rand.randrange(2, phi - 1)


def generate_keys(bits):
    p = get_prime_of_length(bits)
    q = get_prime_of_length(bits)
    while p == q:
        q = get_prime_of_length(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    # e s.t. phi(n) and e are coprime
    e = generate_e(phi)
    g = gcd(e, phi)
    while g != 1:
        e = generate_e(phi)
        g = gcd(e, phi)

    # d is the modular multiplicative inverse
    # d = 1/e mod phi(n)
    d = multiplicative_inverses(e, phi)

    return (n, e), (n, d)


# c = m^e mod n
def encrypt(public_key, plain_text):
    n, e = public_key
    ciphertext = [pow(ord(m), e, n) for m in plain_text]
    return ciphertext


# m = c^d mod n
def decrypt(private_key, ciphertext):
    n, d = private_key
    plain_text = [chr(pow(c, d, n)) for c in ciphertext]
    return ''.join(plain_text)


def read_file(file):
    try:
        with open(file, 'r') as file:
            content = file.read()
        return content
    except IOError:
        raise


def write_file(content, filename):
    try:
        path = os.path.join(sys.argv[2], filename)
        with open(path, 'w') as file:
            file.write(content)
    except IOError:
        raise


def test_rsa():
    bits = 1024
    public_key, private_key = generate_keys(bits)

    try:
        filepath = os.path.join(sys.argv[1], 'noi-vrem-pamant.txt')
        plain_text = read_file(filepath)

        print("-----------------RSA-----------------")
        print("Plain-text:", plain_text)

        enc = encrypt(public_key, plain_text)
        ciphertext = ''.join(map(lambda x: str(x), enc))
        write_file(ciphertext, 'noi-vrem-pamant.txt')
        print("Ciphertext:", ciphertext)

        dec = decrypt(private_key, enc)
        print("Decrypted:", dec)
    except IOError:
        print("Please try again")


if __name__ == '__main__':
    test_rsa()
