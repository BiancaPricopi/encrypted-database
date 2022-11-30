import os
import stat
import sys
from datetime import datetime
from colorama import Fore
from colorama import Style
import hashlib

import mysql.connector

from RSA import generate_keys
from RSA import read_file
from RSA import write_file
from RSA import encrypt
from RSA import decrypt
from exception.DuplicateValueError import DuplicateValueError
from exception.InvalidCommandError import InvalidCommandError

db = mysql.connector.connect(
    host='localhost',
    user='root',
    password='7312022?#M$,',
    database='encrypted_db'
)
cursor = db.cursor()


def check_encrypted_file_existence(file):
    encrypted_location = os.path.join(sys.argv[2], file)
    return os.path.exists(encrypted_location)


def check_plain_file_existence(file):
    location = os.path.join(sys.argv[1], file)
    return os.path.exists(location)


def check_for_duplicates(filepath):
    cursor.execute('SELECT id FROM encryption WHERE TRIM(encrypted_file_location) = %s', (filepath,))
    encrypted_id = cursor.fetchone()
    if encrypted_id is not None:
        raise DuplicateValueError


def write_encryption_details_db(pk, sk, filepath):
    filepath = os.path.abspath(filepath)
    cursor.execute('INSERT INTO encryption(method, type, n, public_key, private_key, encrypted_file_location) '
                   'VALUES(%s, %s, %s, %s, %s, %s) ',
                   ('RSA', 'asymmetric', str(pk[0]), str(pk[1]), str(sk[1]), filepath))
    db.commit()


def convert_date(timestamp):
    modified = datetime.fromtimestamp(timestamp)
    return modified


def write_metadata(filepath):
    filepath = os.path.abspath(filepath)
    filename = os.path.basename(filepath)
    filetype = os.path.splitext(filepath)[1]
    size = os.stat(filepath).st_size
    attributes = os.stat(filepath).st_file_attributes
    owner_uid = os.stat(filepath).st_uid
    owner_group = os.stat(filepath).st_gid
    mode = os.stat(filepath).st_mode
    string_mode = stat.filemode(mode)
    date_created = convert_date(os.stat(filepath).st_ctime)
    date_modified = convert_date(os.stat(filepath).st_mtime)
    date_accessed = convert_date(os.stat(filepath).st_atime)

    encrypted_dir_path = os.path.abspath(sys.argv[2])
    encrypted_file_location = os.path.join(encrypted_dir_path, filename)

    cursor.execute('SELECT id FROM encryption WHERE TRIM(encrypted_file_location) = %s', (encrypted_file_location,))
    encrypted_id = cursor.fetchone()

    cursor.execute('INSERT INTO METADATA(filename, filetype, file_location, size, attributes, '
                   'owner_uid, owner_gid, mode, date_created, date_modified, date_accessed, encryption_id) '
                   'VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                   (filename, filetype, filepath, size, attributes, owner_uid, owner_group, string_mode,
                    date_created, date_modified, date_accessed, encrypted_id[0]))
    db.commit()


def encrypt_file(file):
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
        write_encryption_details_db(public_key, private_key, encrypted_filepath)
        write_metadata(filepath)
        print(f'{Fore.YELLOW}File successfully encrypted.{Style.RESET_ALL}')

    except IOError:
        print("[Error]: File could not be encrypted. Please try again")
    except DuplicateValueError:
        raise


def delete_file(filename):
    abspath = os.path.abspath(sys.argv[2])
    filepath = os.path.join(abspath, filename)
    cursor.execute('DELETE FROM encryption WHERE TRIM(encrypted_file_location) = %s', (filepath,))
    db.commit()


def process_add_command(file):
    try:
        encrypt_file(file)
    except DuplicateValueError:
        answer = input('There is a file with the same name, do you want to override it? (y/n): ')
        while answer not in ('y', 'n'):
            answer = input('There is a file with the same name, do you want to override it? (y/n): ')
        if answer == 'y':
            delete_file(file)
            encrypt_file(file)


def check_if_registered(file):
    cursor.execute('SELECT EXISTS (SELECT encryption_id FROM metadata WHERE TRIM(filename) = %s) '
                   'as OUTPUT', (file,))
    file_registered = cursor.fetchone()
    if file_registered[0] == 0:
        raise FileNotFoundError


def process_read_content_command(file):
    check_if_registered(file)
    cursor.execute('SELECT encryption_id FROM metadata WHERE TRIM(filename) = %s', (file,))
    encryption_id = cursor.fetchone()[0]

    cursor.execute('SELECT n, private_key, encrypted_file_location FROM encryption WHERE id = %s', (encryption_id,))
    n_string, private_key_string, encrypted_filepath = cursor.fetchone()
    n = int(n_string)
    private_key = int(private_key_string)
    with open(encrypted_filepath, 'r') as f:
        encrypted_lines = f.readlines()
        encrypted_array = [int(encrypted_line) for encrypted_line in encrypted_lines]
        dec = decrypt((n, private_key), encrypted_array)
        print(f'{Fore.YELLOW}Content of the file:{Style.RESET_ALL}')
        print(dec)


def compute_hash_for_sk(private_key):
    sha3 = hashlib.sha3_512()
    sha3.update(private_key.encode())
    return sha3.hexdigest()


def process_read_meta_command(file):
    check_if_registered(file)
    cursor.execute('SELECT * FROM metadata m JOIN encryption e ON m.encryption_id = e.id AND TRIM(m.filename) = %s',
                   (file,))
    metadata = cursor.fetchone()
    private_key = compute_hash_for_sk(metadata[18])
    print(f'{Fore.YELLOW}Metadata:{Style.RESET_ALL}')
    print(f'{Fore.RED}Name:{Style.RESET_ALL} {metadata[1]}')
    print(f'{Fore.RED}Type:{Style.RESET_ALL} {metadata[2]}')
    print(f'{Fore.RED}File location:{Style.RESET_ALL} {metadata[3]}')
    print(f'{Fore.RED}Size:{Style.RESET_ALL} {metadata[4]}')
    print(f'{Fore.RED}Attributes:{Style.RESET_ALL} {metadata[5]}')
    print(f'{Fore.RED}Owner uid:{Style.RESET_ALL} {metadata[6]}')
    print(f'{Fore.RED}Owner gid:{Style.RESET_ALL} {metadata[7]}')
    print(f'{Fore.RED}Mode:{Style.RESET_ALL} {metadata[8]}')
    print(f'{Fore.RED}Date created:{Style.RESET_ALL} {metadata[9]}')
    print(f'{Fore.RED}Date modified:{Style.RESET_ALL} {metadata[10]}')
    print(f'{Fore.RED}Date accessed:{Style.RESET_ALL} {metadata[11]}')
    print(f'{Fore.RED}Method used for encryption:{Style.RESET_ALL} {metadata[14]}')
    print(f'{Fore.RED}Encryption type:{Style.RESET_ALL} {metadata[15]}')
    print(f'{Fore.RED}Public key modulus:{Style.RESET_ALL} {metadata[16]}')
    print(f'{Fore.RED}Public key exponent:{Style.RESET_ALL} {metadata[17]}')
    print(f'{Fore.RED}Private key:{Style.RESET_ALL} {private_key}')
    print(f'{Fore.RED}Encrypted file location:{Style.RESET_ALL} {metadata[19]}')


def process_remove_command(file):
    check_if_registered(file)
    cursor.execute('SELECT encryption_id FROM metadata WHERE TRIM(filename) = %s', (file,))
    encryption_id = cursor.fetchone()[0]
    cursor.execute('SELECT encrypted_file_location FROM encryption WHERE id = %s', (encryption_id,))
    encrypted_filepath = cursor.fetchone()[0]

    if os.path.exists(encrypted_filepath):
        os.remove(encrypted_filepath)
        cursor.execute('DELETE FROM encryption WHERE id = %s', (encryption_id,))
        db.commit()
        print(f'{Fore.LIGHTYELLOW_EX}File {file} successfully deleted from database{Style.RESET_ALL}')
    else:
        raise FileNotFoundError


def process_help_command():
    print(f'{Fore.YELLOW}Encrypted database (c){Style.RESET_ALL}\n'
          'enc -add <file> : add the file to encrypted database\n'
          'enc -read-file <file> : read content of the encrypted file\n'
          'enc -read-meta <file> : read metadata (properties) of the file\n'
          'enc -rm <file> : delete the file from encrypted database\n'
          'help : display a list of the available commands')


def process_commands(command, file):
    try:
        if command == '-add':
            process_add_command(file)
        elif command == '-read-file':
            process_read_content_command(file)
        elif command == '-read-meta':
            process_read_meta_command(file)
        elif command == '-read':
            process_read_meta_command(file)
            print()
            process_read_content_command(file)
        elif command == '-rm':
            process_remove_command(file)
        else:
            print('Not implemented yet')
    except Exception:
        raise


def validate_user_input(enc, command, file):
    if enc != 'enc':
        raise SyntaxError
    if command not in ['-add', '-read-file', '-read-meta', '-read', '-rm']:
        raise InvalidCommandError
    if not check_plain_file_existence(file):
        raise FileNotFoundError
    filepath = os.path.join(sys.argv[1], file)
    if not os.path.isfile(filepath):
        raise IsADirectoryError


def terminal():
    print('Type \'help\' to list available commands')
    while True:
        try:
            user_input = input(">>:")
            enc, command, file = user_input.split()
            validate_user_input(enc, command, file)
            process_commands(command, file)
        except SyntaxError:
            print(f'[Error]: You have a syntax error. \'{enc}\' is not recognized')
            print('Type \'help\' to list available commands')
        except InvalidCommandError:
            print(f'[Error]: {command} not recognized as an internal command')
            print('Type \'help\' to list available commands')
        except FileNotFoundError:
            print('[Error]: File not found. Please try again')
        except IsADirectoryError:
            print('[Error]: Directories are not allowed')
        except ValueError:
            if user_input == 'q':
                print('Bye')
                break
            if user_input == 'help':
                process_help_command()
            print('[Error]: Watch out the number of args')
            print('Type \'help\' to list available commands')
    db.close()


terminal()
