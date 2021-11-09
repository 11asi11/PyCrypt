import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from colorama import Fore, init


def banner():
    return """
    
 ██▓███ ▓██   ██▓ ▄████▄   ██▀███ ▓██   ██▓ ██▓███  ▄▄▄█████▓
▓██░  ██▒▒██  ██▒▒██▀ ▀█  ▓██ ▒ ██▒▒██  ██▒▓██░  ██▒▓  ██▒ ▓▒
▓██░ ██▓▒ ▒██ ██░▒▓█    ▄ ▓██ ░▄█ ▒ ▒██ ██░▓██░ ██▓▒▒ ▓██░ ▒░
▒██▄█▓▒ ▒ ░ ▐██▓░▒▓▓▄ ▄██▒▒██▀▀█▄   ░ ▐██▓░▒██▄█▓▒ ▒░ ▓██▓ ░ 
▒██▒ ░  ░ ░ ██▒▓░▒ ▓███▀ ░░██▓ ▒██▒ ░ ██▒▓░▒██▒ ░  ░  ▒██▒ ░ 
▒▓▒░ ░  ░  ██▒▒▒ ░ ░▒ ▒  ░░ ▒▓ ░▒▓░  ██▒▒▒ ▒▓▒░ ░  ░  ▒ ░░   
░▒ ░     ▓██ ░▒░   ░  ▒     ░▒ ░ ▒░▓██ ░▒░ ░▒ ░         ░    
░░       ▒ ▒ ░░  ░          ░░   ░ ▒ ▒ ░░  ░░         ░      
         ░ ░     ░ ░         ░     ░ ░                       
         ░ ░     ░                 ░ ░                       
"""


def status_fail():
    return Fore.WHITE + "[" + Fore.RED + " FAILED " + Fore.WHITE + "]"


def status_ok():
    return Fore.WHITE + "[" + Fore.GREEN + " OK " + Fore.WHITE + "]"


def status_note():
    return Fore.WHITE + "[ * ]"


def status_pause():
    input(Fore.WHITE + "press [" + Fore.GREEN + "ENTER" + Fore.WHITE + "] to continue")


def generate_key_from_password(password: str):
    salt = b'>\xe7O@_\xb4bU\xa5q\x02\xa6\xa4\x95\x1d\xfd'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def load_file(file_path):
    f = open(file_path, "rb")
    b = f.read()
    f.close()
    return b


def save_file(file_path, data):
    f = open(file_path, "wb")
    f.write(data)
    f.close()


def menu():
    print(Fore.WHITE + "\nMenu:")
    print(Fore.GREEN + "1)" + Fore.WHITE + " encrypt file")
    print(Fore.GREEN + "2)" + Fore.WHITE + " decrypt file")
    print(Fore.GREEN + "exit)" + Fore.WHITE + " exit PyCrypt")
    return input(Fore.WHITE + "choose: " + Fore.GREEN)


def option_1():
    file_path = input(status_note() + " enter the path to the file you want to encrypt: " + Fore.GREEN)
    while not os.path.exists(file_path):
        print(status_fail() + " file does not exists")
        file_path = input(status_note() + " enter the path to the file you want to encrypt: " + Fore.GREEN)
    print(status_ok() + " file found")

    password = input(status_note() + " password: " + Fore.GREEN)
    f = Fernet(generate_key_from_password(password))
    encrypted_file_data = f.encrypt(load_file(file_path))
    print(status_ok() + " file encrypted successfully")

    encrypted_file_path = input(status_note() + " enter the path you want to save the encrypted file in: " + Fore.GREEN)
    save_file(encrypted_file_path, encrypted_file_data)
    print(status_ok() + " the file was saved successfully")


def option_2():
    file_path = input(status_note() + " enter the path to the file you want to decrypt: " + Fore.GREEN)
    while not os.path.exists(file_path):
        print(status_fail() + " file does not exists")
        file_path = input(status_note() + " enter the path to the file you want to decrypt: " + Fore.GREEN)
    print(status_ok() + " file found")

    password = input(status_note() + " password: " + Fore.GREEN)
    f = Fernet(generate_key_from_password(password))
    decrypted_file_data = f.decrypt(load_file(file_path))
    print(status_ok() + " file encrypted successfully")

    decrypted_file_path = input(status_note() + " enter the path you want to save the decrypted file in: " + Fore.GREEN)
    save_file(decrypted_file_path, decrypted_file_data)
    print(status_ok() + " the file was saved successfully")


def main():
    try:
        while True:
            os.system("cls" or "clear")
            print(Fore.RED + banner())
            menu_option = menu()
            if menu_option == "1":
                option_1()
            elif menu_option == "2":
                option_2()
            elif menu_option == "exit":
                exit()
            else:
                print(status_fail() + " unknown command: " + menu_option)
    except KeyboardInterrupt: # if Ctrl+C is pressed stop the program
        print(Fore.RED + "\nInterrupted" + Fore.WHITE)
        exit()
    finally:
        print(Fore.WHITE, end="") # change the color back to white


if __name__ == "__main__":
    main()
