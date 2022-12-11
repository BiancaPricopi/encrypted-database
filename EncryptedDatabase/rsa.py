import os
import random as rand
import sys

from Crypto.Util import number


def get_prime_of_length(length):
    """
    Get a prime number of a specific length.

    :param length: length of the number
    :return: a prime number of a specific length
    """
    return number.getPrime(length)


def gcd(a, b):
    """
    Compute the greatest common divisor.

    :param a: first number
    :param b: second number
    """
    while b != 0:
        a, b = b, a % b
    return a


def gcd_extended(a, b):
    """
    Extended Euclidean algorithm.

    :param a: first number
    :param b: second number
    :return: a tuple containing gcd and Bezout coefficients
    """
    # (g, x, y) a.i. a*x + b*y = g = gcd(a, b)
    old_s, s = 1, 0
    old_t, t = 0, 1
    while b != 0:
        (quotient, b), a = divmod(a, b), b
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return a, old_s, old_t


def multiplicative_inverses(a, b):
    """
    Computes the multiplicative inverse.

    :param a: first number
    :param b: second number
    :return: the multiplicative inverse
    """
    _, x, _ = gcd_extended(a, b)
    return x % b


def generate_e(phi):
    """
    Generates a random number smaller than phi.

    :param phi: phi number
    :return: a random number smaller than phi
    """
    return rand.randrange(2, phi - 1)


def generate_keys(bits):
    """
    Generates public key and private key for RSA.

    :param bits: the length for p and q
    :return: two tuples representing public key and private key
    """
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


def encrypt(public_key, plain_text):
    """
    RSA encryption.

    :param public_key: the public key
    :param plain_text: message to be encrypted
    :return: ciphertext
    """
    n, e = public_key
    # c = m^e mod n
    ciphertext = [pow(ord(m), e, n) for m in plain_text]
    return ciphertext


def decrypt(private_key, ciphertext):
    """
    RSA decryption.

    :param private_key: the private key
    :param ciphertext: ciphertext to be decrypted
    :return: plaintext
    """
    n, d = private_key
    # m = c^d mod n
    plain_text = [chr(pow(c, d, n)) for c in ciphertext]
    return ''.join(plain_text)


def read_file(file):
    """
    Reads content of a file.

    :param file: the absolute path of the file
    :return: the content of the file
    """
    try:
        with open(file, 'r') as file:
            content = file.read()
        return content
    except IOError:
        raise


def write_file(content, filename):
    """
    Writes content into a file.

    :param content: the content of the file
    :param filename: the absolute path of the file
    """
    try:
        path = os.path.join(sys.argv[2], filename)
        with open(path, 'w') as file:
            for encrypted_letter in content:
                file.write(str(encrypted_letter) + '\n')
    except IOError:
        raise
