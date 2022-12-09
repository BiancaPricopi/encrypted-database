import os

from colorama import Fore, Style

from database.db_operations import connect_to_db, check_if_registered


def process_remove_command(file):
    """
    Deletes a file from encrypted database and from disk location.

    :param file: the name of the file
    """
    db, cursor = connect_to_db()
    check_if_registered(file)
    cursor.execute(
        'SELECT encryption_id FROM metadata WHERE TRIM(filename) = %s', (file,)
    )
    encryption_id = cursor.fetchone()[0]
    cursor.execute(
        'SELECT encrypted_file_location FROM encryption WHERE id = %s',
        (encryption_id,)
    )
    encrypted_filepath = cursor.fetchone()[0]

    if os.path.exists(encrypted_filepath):
        os.remove(encrypted_filepath)
        cursor.execute('DELETE FROM encryption WHERE id = %s',
                       (encryption_id,))
        db.commit()
        db.close()
        print(
            f'{Fore.GREEN}File {file} successfully deleted from database'
            f'{Style.RESET_ALL}'
        )
    else:
        db.close()
        raise FileNotFoundError
