import os
import sys
from colorama import Fore
from colorama import Style


from command.add import process_add_command
from command.delete import process_remove_command
from command.read import process_read_meta_command, \
    process_read_content_command
from exception.InvalidCommandError import InvalidCommandError
from exception.DirectoryNotFound import DirectoryNotFound


def check_args():
    """Validates command line arguments."""
    if len(sys.argv) != 3:
        raise TypeError(
            f'{Fore.RED}[Error]: Not enough arguments. '
            'Please enter one directory for Plain files and '
            f'one directory for Encrypted Files in this order{Style.RESET_ALL}'
        )
    if not os.path.exists(sys.argv[1]) or not os.path.exists(sys.argv[2]):
        raise DirectoryNotFound
    if not os.path.isdir(sys.argv[1]) or not os.path.isdir(sys.argv[2]):
        raise NotADirectoryError


def check_encrypted_file_existence(file):
    """
    Verifies if the file exists at the location of the encrypted files.

    :param file: the name of the file that will be verified
    """
    encrypted_location = os.path.join(sys.argv[2], file)
    return os.path.exists(encrypted_location)


def check_plain_file_existence(file):
    """
    Verifies if the file exists at the location of the plain files.

    :param file: the name of the file that will be verified
    """
    location = os.path.join(sys.argv[1], file)
    return os.path.exists(location)


def process_help_command():
    """Prints the available commands. """
    print(
        f'{Fore.YELLOW}Encrypted database (c)\n'
        'enc -add <file> : add the file to encrypted database\n'
        'enc -read-file <file> : display content of the encrypted file\n'
        'enc -read-meta <file> : display metadata (properties) of the file\n'
        'enc -read <file> : display content and metadata of the file\n'
        'enc -rm <file> : delete the file from encrypted database\n'
        f'help : display a list of the available command\n'
        f'q : to exit{Style.RESET_ALL}'
    )


def process_commands(command, file):
    """
    Execute a specific action from the list on a file.

    :param command: action to be executed
    :param file: the name of the file
    """
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
    """
    Validates user input.

    :param enc: must be equal with 'enc'
    :param command: action to be executed
    :param file: the name of the file
    """
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
    """Display user-terminal interaction"""
    print('Type "help" to list available command')
    while True:
        try:
            user_input = input(f'{Fore.YELLOW}>>:{Style.RESET_ALL}')
            enc, command, file = user_input.split()
            validate_user_input(enc, command, file)
            process_commands(command, file)
        except SyntaxError:
            print(
                f'{Fore.RED}[Error]: You have a syntax error. '
                f'"{enc}" is not recognized{Style.RESET_ALL}'
            )
            print('Type "help" to list available command')
        except InvalidCommandError:
            print(
                f'{Fore.RED}[Error]: {command} not recognized '
                f'as an internal command{Style.RESET_ALL}'
            )
            print('Type "help" to list available command')
        except DirectoryNotFound:
            print(
                f'{Fore.RED}[Error]: Directory not found. '
                f'Please try again{Style.RESET_ALL}'
            )
        except FileNotFoundError:
            print(
                f'{Fore.RED}[Error]: File not found. '
                f'Please try again{Style.RESET_ALL}'
            )
        except IsADirectoryError:
            print(
                f'{Fore.RED}[Error]: Directories are not allowed'
                f'{Style.RESET_ALL}')
        except NotADirectoryError:
            print(
                f'{Fore.RED}[Error]: Please enter two valid directories'
                f'{Style.RESET_ALL}'
            )
        except ValueError:
            if user_input.lower() == 'q':
                print(f'{Fore.YELLOW}Bye{Style.RESET_ALL}')
                break
            elif user_input == 'help':
                process_help_command()
            else:
                print(
                    f'{Fore.RED}[Error]: Watch out the number of args'
                    f'{Style.RESET_ALL}'
                )
                print('Type "help" to list available command.')


if __name__ == '__main__':
    try:
        check_args()
        terminal()
    except DirectoryNotFound:
        print(
            f'{Fore.RED}[Error]: Directory not found. '
            f'Please try again{Style.RESET_ALL}'
        )
    except NotADirectoryError:
        print(
            f'{Fore.RED}[Error]: Please enter two valid directories'
            f'{Style.RESET_ALL}'
        )
    except TypeError as e:
        print(f'{Fore.RED}{e}{Style.RESET_ALL}')
