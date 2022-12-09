import os
import stat
import sys

import mysql.connector
from dotenv import load_dotenv

from exception.DuplicateValueError import DuplicateValueError
from utils import convert_date


def connect_to_db():
    """
    Connects to encrypted db.

    :return: db connector and cursor
    """
    load_dotenv()
    db = mysql.connector.connect(
        host='localhost',
        user='root',
        password=os.getenv('db_password'),
        database='encrypted_db'
    )
    cursor = db.cursor()
    return db, cursor


def write_encryption_details_db(pk, sk, filepath):
    """
    Writes encrypted details about a file in database.

    :param pk: public key for RSA
    :param sk: secret key for RSA
    :param filepath: location of the encrypted file
    """
    db, cursor = connect_to_db()
    filepath = os.path.abspath(filepath)
    cursor.execute(
        'INSERT INTO encryption(method, type, n, public_key, private_key, '
        'encrypted_file_location) VALUES(%s, %s, %s, %s, %s, %s) ',
        ('RSA', 'asymmetric', str(pk[0]),
         str(pk[1]), str(sk[1]), filepath
         )
    )
    db.commit()
    db.close()


def write_metadata(filepath):
    """
    Writes metadata associated with a file into database.

    :param filepath: location of the plain file
    """
    db, cursor = connect_to_db()
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

    cursor.execute(
        'SELECT id FROM encryption WHERE TRIM(encrypted_file_location) = %s',
        (encrypted_file_location,)
    )
    encrypted_id = cursor.fetchone()

    cursor.execute(
        'INSERT INTO METADATA(filename, filetype, file_location, size, '
        'attributes, owner_uid, owner_gid, mode, date_created, date_modified, '
        'date_accessed, encryption_id) '
        'VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
        (filename, filetype, filepath, size, attributes, owner_uid,
         owner_group, string_mode, date_created, date_modified, date_accessed,
         encrypted_id[0],
         )
    )
    db.commit()
    db.close()


def check_for_duplicates(filepath):
    """
    Verifies if there is already an encrypted file at the same location.

    :param filepath: the path of the file that will be verified
    """
    db, cursor = connect_to_db()
    cursor.execute(
        'SELECT id FROM encryption WHERE TRIM(encrypted_file_location) = %s',
        (filepath,)
    )
    encrypted_id = cursor.fetchone()
    if encrypted_id is not None:
        raise DuplicateValueError
    db.close()


def delete_file(filename):
    """
    Deletes all records of a file from encrypted database.

    :param filename: the name of the file
    """
    db, cursor = connect_to_db()
    abspath = os.path.abspath(sys.argv[2])
    filepath = os.path.join(abspath, filename)
    cursor.execute(
        'DELETE FROM encryption WHERE TRIM(encrypted_file_location) = %s',
        (filepath,)
    )
    db.commit()
    db.close()


def check_if_registered(file):
    """
    Verifies if there is a file in the database with the same name.

    :param file: the name of the file
    """
    db, cursor = connect_to_db()
    cursor.execute(
        'SELECT EXISTS (SELECT encryption_id FROM metadata '
        'WHERE TRIM(filename) = %s) as OUTPUT',
        (file,)
    )
    file_registered = cursor.fetchone()
    if file_registered[0] == 0:
        raise FileNotFoundError
    db.close()
