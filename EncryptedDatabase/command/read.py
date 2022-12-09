from colorama import Fore, Style

from database.db_operations import connect_to_db, check_if_registered
from rsa import decrypt
from utils import compute_hash_for_sk


def process_read_content_command(file):
    """
    Prints the decrypted content of an encrypted file.

    :param file: the name of the encrypted file
    """
    check_if_registered(file)
    db, cursor = connect_to_db()
    cursor.execute(
        'SELECT encryption_id FROM metadata WHERE TRIM(filename) = %s', (file,)
    )
    encryption_id = cursor.fetchone()[0]

    cursor.execute(
        'SELECT n, private_key, encrypted_file_location FROM encryption '
        'WHERE id = %s', (encryption_id,)
    )
    n_string, private_key_string, encrypted_filepath = cursor.fetchone()
    n = int(n_string)
    private_key = int(private_key_string)
    db.close()
    with open(encrypted_filepath, 'r') as f:
        encrypted_lines = f.readlines()
        encrypted_array = [int(encrypted_line) for encrypted_line in
                           encrypted_lines]
        plain_text = decrypt((n, private_key), encrypted_array)
        print(
            f'{Fore.YELLOW}Content of the file:{Style.RESET_ALL}\n'
            f'{plain_text}'
        )


def process_read_meta_command(file):
    """
    Prints the metadata of the file

    :param file: the name of the file
    """
    check_if_registered(file)
    db, cursor = connect_to_db()
    cursor.execute(
        'SELECT * FROM metadata m JOIN encryption e ON m.encryption_id = e.id '
        'AND TRIM(m.filename) = %s', (file,)
    )
    metadata = cursor.fetchone()
    private_key = compute_hash_for_sk(metadata[18])
    print(f'{Fore.YELLOW}Metadata:')
    print(f'{Fore.GREEN}Name:{Style.RESET_ALL} {metadata[1]}')
    print(f'{Fore.GREEN}Type:{Style.RESET_ALL} {metadata[2]}')
    print(f'{Fore.GREEN}File location:{Style.RESET_ALL} {metadata[3]}')
    print(f'{Fore.GREEN}Size:{Style.RESET_ALL} {metadata[4]}')
    print(f'{Fore.GREEN}Attributes:{Style.RESET_ALL} {metadata[5]}')
    print(f'{Fore.GREEN}Owner uid:{Style.RESET_ALL} {metadata[6]}')
    print(f'{Fore.GREEN}Owner gid:{Style.RESET_ALL} {metadata[7]}')
    print(f'{Fore.GREEN}Mode:{Style.RESET_ALL} {metadata[8]}')
    print(f'{Fore.GREEN}Date created:{Style.RESET_ALL} {metadata[9]}')
    print(f'{Fore.GREEN}Date modified:{Style.RESET_ALL} {metadata[10]}')
    print(f'{Fore.GREEN}Date accessed:{Style.RESET_ALL} {metadata[11]}')
    print(
        f'{Fore.GREEN}Method used for encryption:{Style.RESET_ALL} '
        f'{metadata[14]}'
    )
    print(f'{Fore.GREEN}Encryption type:{Style.RESET_ALL} {metadata[15]}')
    print(f'{Fore.GREEN}Public key modulus:{Style.RESET_ALL} {metadata[16]}')
    print(f'{Fore.GREEN}Public key exponent:{Style.RESET_ALL} {metadata[17]}')
    print(f'{Fore.GREEN}Private key:{Style.RESET_ALL} {private_key}')
    print(
        f'{Fore.GREEN}Encrypted file location:{Style.RESET_ALL} '
        f'{metadata[19]}'
    )
