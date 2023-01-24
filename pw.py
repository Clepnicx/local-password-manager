__author__ = "Flemming Jäger"

import base64
import shelve
import sys
import time
import stdiomask
import save
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class MasterPassword:
    def __init__(self, passkey):
        self.passkey = passkey

        self.call_master()

    def call_master(self):

        shelf = shelve.open("save.db", flag="r")
        shelf_keys = shelf.keys()
        if "passkey" in shelf_keys:
            key = shelf.get("passkey")
            self.passkey = key
        else:
            print("No Master-Password set!")
            self.new_master()

        entered_password = stdiomask.getpass("Enter the Master-Password: ", mask="*")
        entered_password_bytes = entered_password.encode()
        salt = b'\xe0\t\xd1Fm\xce\xdeNQ\xf5\x1f\x0f\xf6\xa8z\xfa'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        entered_key = base64.urlsafe_b64encode(kdf.derive(entered_password_bytes))

        if entered_key == self.passkey:
            print("The password was correct!")
            time.sleep(2)
        else:
            print("ERROR: The password was incorrect!")
            time.sleep(2)
            sys.exit()

    def new_master(self):

        password_provided = input("Create the new Master-Password: ")

        while True:
            confirmation = input(f"Are you shure you want to use the Master-Password: {password_provided} (J/n): ")
            try:
                if confirmation in ["J", "j", "y", "Y"]:
                    break
                else:
                    raise ValueError
            except ValueError:
                password_provided = input("Create the new Master-Password: ")

        new_password = password_provided.encode()

        salt = b'\xe0\t\xd1Fm\xce\xdeNQ\xf5\x1f\x0f\xf6\xa8z\xfa'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(new_password))

        shelf = shelve.open("save.db")

        shelf["passkey"] = key

        shelf.close()

        self.passkey = key

        print("The Master-Password was created successfully!")
        time.sleep(2)
        input("--press ENTER to continue--")


class Account:
    def __init__(self, password, user_name):
        self.password = password
        self.user_name = user_name

    def change_password(self):
        password_provided = input("Enter the new password: ")

        while True:
            confirmation = input(f"Is the password: {password_provided} correct? (J/n): ")
            try:
                if confirmation in ["J", "j", "y", "Y"]:
                    break
                else:
                    raise ValueError
            except ValueError:
                password_provided = input("Enter the new password: ")

        encoded_password = password_provided.encode()

        shelf = shelve.open("save.db", flag="r")
        key = shelf["passkey"]
        shelf.close()

        f = Fernet(key)
        encrypted_password = f.encrypt(encoded_password)

        self.password = encrypted_password

    def change_username(self):
        new_username = input("Enter the new username: ")

        while True:
            confirmation = input(f"Is the username: {new_username}, correct? (J/n): ")
            try:
                if confirmation in ["J", "j", "y", "Y"]:
                    break
                else:
                    raise ValueError
            except ValueError:
                new_username = input("Enter the new username: ")

        self.user_name = new_username


def menu():

    print("*********************\n"
          "***Passwordmanager***\n"
          "*********************\n")
    while True:
        print("Function (command): \n"
              "- Save new password. (save) \n"
              "- Recall password. (call) \n"
              "- List all accounts. (list)\n"
              "- configure/delete account. (redo)\n"
              "\n"
              "--press q to qiut--\n")

        while True:
            x = input("Enter a command: ")

            try:
                if x in ["save", "call", "list", "q", "redo"]:
                    break
                else:
                    raise ValueError

            except ValueError:
                pass

        if x == "save":
            save_account()
            print("*" * 100)

        elif x == "call":
            call_password()
            print("*" * 100)

        elif x == "list":
            list_accounts()
            print("*" * 100)

        elif x == "redo":
            manage_account()
            print("*" * 100)

        elif x == "q":
            print("quitting...")
            time.sleep(1)
            sys.exit()


def save_account():

    account = input("For which account would you like to create an entry?: ")
    username = input("Is there a username? (If not, enter (-, no)): ")
    password = input("Enter the password:")

    while True:
        confirmation = input(f"Is the password correct?: {password}, (J/n): ")
        try:
            if confirmation == "J":
                break
            else:
                raise ValueError
        except ValueError:
            password = input("Enter the password:")

    encrypted_password = encrypt(password)

    shelf = shelve.open("save.db")
    shelf_entry = Account(encrypted_password, username)
    shelf[account] = shelf_entry
    shelf.close()


def call_password():

    shelf = shelve.open("save.db", flag="r")

    while True:
        account = input("For which account would you like to retrieve the password?:")
        try:
            if account in shelf:
                break
            else:
                raise ValueError
        except ValueError:
            pass

    wanted_account = shelf.get(account)

    password = decrypt(wanted_account.password)
    print(f"Username: {wanted_account.user_name}, Password: {password}")
    shelf.close()

    input("--press ENTER to continue--")


def list_accounts():

    shelf = shelve.open("save.db", flag="r")
    list_names = shelf.keys()

    print("############################\n"
          "List of accounts:\n")
    for i in list_names:
        if i == "passkey":
            pass
        else:
            print(f"- {i}")
    print("############################")

    shelf.close()


def manage_account():

    shelf = shelve.open("save.db")

    while True:
        account = input("Which account do you want to edit/delete?: ")
        try:
            if account in shelf:
                break
            else:
                raise ValueError
        except ValueError:
            pass

    wanted_account = shelf.get(account)

    print("*" * 100)
    print("What action would you like to take?:\n"
          "- Change username. (user)\n"
          "- Change password (pass)\n"
          "- Delete account. (del)\n"
          "\n")

    while True:
        action = input("Enter a command: ")
        try:
            if action in ["user", "pass", "del"]:
                break
            else:
                raise ValueError
        except ValueError:
            pass

    if action == "user":

        wanted_account.change_username()
        shelf = shelve.open("save.db")
        shelf[account] = wanted_account
        shelf.close()

    elif action == "pass" or "del":

        while True:
            safety = stdiomask.getpass("Enter the password for the account: ", mask="*")
            decrypted_account_pass = decrypt(wanted_account.password)
            try:
                if safety == decrypted_account_pass:
                    break
                else:
                    raise ValueError
            except ValueError:
                print(f"ERROR: Wrong password for '{account}'!")

        if action == "pass":

            wanted_account.change_password()

            shelf = shelve.open("save.db")
            shelf[account] = wanted_account
            shelf.close()

        elif action == "del":

            print("Account entry is deleted...")
            shelf = shelve.open("save.db")
            del shelf[account]
            shelf.close()
            time.sleep(2)
            print("Account entry has been deleted!")

            input("--press ENTER to continue--")


def encrypt(password):

    encoded_password = password.encode()

    shelf = shelve.open("save.db", flag="r")
    key = shelf["passkey"]
    shelf.close()

    f = Fernet(key)
    encrypted_password = f.encrypt(encoded_password)

    return encrypted_password


def decrypt(encrypted_password):

    shelf = shelve.open("save.db", flag="r")
    key = shelf["passkey"]
    shelf.close()

    f = Fernet(key)
    encoded_password = f.decrypt(encrypted_password)
    decoded_password = encoded_password.decode()

    return decoded_password


def check_source():

    try:
        shelve.open("save.db")
    except FileNotFoundError:
        save.create_db()


def main():
    check_source()
    MasterPassword(passkey=None)
    menu()


if __name__ == "__main__":
    main()
