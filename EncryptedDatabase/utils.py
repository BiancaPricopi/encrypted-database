import hashlib
from datetime import datetime


def convert_date(timestamp):
    """
    Converts timestamp to a readable datetime format.

    :param timestamp: number of seconds
    :return: datetime format
    """
    modified = datetime.fromtimestamp(timestamp)
    return modified


def compute_hash_for_sk(private_key):
    """
    Computes sha3-512 hash function.

    :param private_key: private key
    :return: unique hash
    """
    sha3 = hashlib.sha3_512()
    sha3.update(private_key.encode())
    return sha3.hexdigest()
