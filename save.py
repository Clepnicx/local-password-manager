__author__ = "Flemming Jäger"

import shelve


def create_db():
    shelf = shelve.open("save.db")
    print(type(shelf), "was created!")

