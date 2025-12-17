# vulnerable_app.py
import os

def greet_user():
    name = input("Enter your name: ")

    # ❌ VULNERABILITY: Command Injection
    # User input is directly passed to the system shell
    os.system("echo Hello " + name)

if __name__ == "__main__":
    greet_user()
