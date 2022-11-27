import mysql.connector


def create_db():
    db = mysql.connector.connect(
        host='localhost',
        user='root',
        password='7312022?#M$,'
    )
    cursor = db.cursor()
    cursor.execute('DROP DATABASE IF EXISTS encrypted_db')
    cursor.execute('CREATE DATABASE encrypted_db')
    db.close()


def create_tables():
    db = mysql.connector.connect(
        host='localhost',
        user='root',
        password='7312022?#M$,',
        database='encrypted_db'
    )
    cursor = db.cursor()
    cursor.execute('DROP TABLE IF EXISTS METADATA')
    cursor.execute('DROP TABLE IF EXISTS ENCRYPTION')
    cursor.execute('CREATE TABLE ENCRYPTION (id INT PRIMARY KEY AUTO_INCREMENT, method VARCHAR(50), type VARCHAR(50), '
                   'public_key INT, private_key INT, encrypted_file_location VARCHAR(255))')
    cursor.execute('CREATE TABLE METADATA (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(50), type VARCHAR(50), '
                   'file_location VARCHAR(255), size FLOAT, date_created TIMESTAMP, date_modified TIMESTAMP, '
                   'attributes VARCHAR(50), owner VARCHAR(50), computer VARCHAR(50), encryption_id INT,'
                   ' FOREIGN KEY (encryption_id) REFERENCES ENCRYPTION(id) ON DELETE CASCADE)')
    db.close()


def init():
    create_db()
    create_tables()
