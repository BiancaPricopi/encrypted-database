import mysql.connector
import os
from dotenv import load_dotenv


def create_db():
    """Creates the encrypted database."""
    load_dotenv()
    db = mysql.connector.connect(
        host='localhost',
        user='root',
        password=os.getenv('db_password')
    )
    cursor = db.cursor()
    cursor.execute('DROP DATABASE IF EXISTS encrypted_db')
    cursor.execute('CREATE DATABASE encrypted_db')
    db.close()


def create_tables():
    """Creates tables for the encrypted database."""
    load_dotenv()
    db = mysql.connector.connect(
        host='localhost',
        user='root',
        password=os.getenv('db_password'),
        database='encrypted_db'
    )
    cursor = db.cursor()
    cursor.execute('DROP TABLE IF EXISTS METADATA')
    cursor.execute('DROP TABLE IF EXISTS ENCRYPTION')
    cursor.execute(
        'CREATE TABLE ENCRYPTION '
        '(id INT PRIMARY KEY AUTO_INCREMENT, '
        'method VARCHAR(50), type VARCHAR(50), '
        'n LONGTEXT, public_key LONGTEXT, private_key LONGTEXT, '
        'encrypted_file_location VARCHAR(255) UNIQUE)'
    )
    cursor.execute(
        'CREATE TABLE METADATA '
        '(id INT PRIMARY KEY AUTO_INCREMENT, filename VARCHAR(50) UNIQUE, '
        'filetype VARCHAR(50), file_location VARCHAR(255)  UNIQUE, '
        'size FLOAT, attributes INT UNSIGNED, '
        'owner_uid INT UNSIGNED, owner_gid INT UNSIGNED, mode VARCHAR(50), '
        'date_created TIMESTAMP, date_modified TIMESTAMP, '
        'date_accessed TIMESTAMP, encryption_id INT NOT NULL, '
        'FOREIGN KEY (encryption_id) '
        'REFERENCES encryption(id) ON DELETE CASCADE)'
    )
    db.close()


def init():
    """Initialize the encrypted database"""
    create_db()
    create_tables()
