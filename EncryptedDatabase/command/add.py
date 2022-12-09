import os
import sys
from colorama import Fore
from colorama import Style

from database.db_operations import delete_file, write_metadata, \
    write_encryption_details_db, check_for_duplicates
from exception.DuplicateValueError import DuplicateValueError
from rsa import generate_keys, read_file, encrypt, write_file


def encrypt_file(file):
    """
    Encrypt the file using RSA.

    :param file: the name of the file
    """
    bits = 1024
    public_key, private_key = generate_keys(bits)

    try:
        encrypted_dir_path = os.path.abspath(sys.argv[2])
        encrypted_filepath = os.path.join(encrypted_dir_path, file)
        check_for_duplicates(encrypted_filepath)

        dir_path = os.path.abspath(sys.argv[1])
        filepath = os.path.join(dir_path, file)
        plain_text = read_file(filepath)

        enc = encrypt(public_key, plain_text)
        write_file(enc, file)
        write_encryption_details_db(public_key, private_key,
                                    encrypted_filepath)
        write_metadata(filepath)
        print(f'{Fore.GREEN}File successfully encrypted.{Style.RESET_ALL}')

    except IOError:
        print(
            f'{Fore.RED}[Error]: File could not be encrypted. '
            f'Please try again{Style.RESET_ALL}'
        )
    except DuplicateValueError:
        raise


def process_add_command(file):
    """
    Adds a file to the encrypted database.

    :param file: the name of the file
    """
    try:
        encrypt_file(file)
    except DuplicateValueError:
        answer = input(
            f'{Fore.YELLOW}There is a file with the same name, '
            f'do you want to override it? (y/n): {Style.RESET_ALL}'
        )
        while answer not in ('y', 'n'):
            answer = input(
                f'{Fore.YELLOW}There is a file with the same name, '
                f'do you want to override it? (y/n): {Style.RESET_ALL}'
            )
        if answer == 'y':
            delete_file(file)
            encrypt_file(file)
