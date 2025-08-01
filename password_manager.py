import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet
import secrets
import string

DB_FILE = "passwords.db"
MASTER_FILE = "master.key"

# ---------- Helper Functions ----------
def create_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS credentials
                   (id INTEGER PRIMARY KEY, website TEXT, username TEXT, password TEXT)''')
    conn.commit()
    conn.close()

def get_key(master_password):
    # Generate 32-byte key using SHA256 hash of master password
    return hashlib.sha256(master_password.encode()).digest()

def encrypt_password(key, plain_text):
    fernet = Fernet(base64.urlsafe_b64encode(key))
    return fernet.encrypt(plain_text.encode()).decode()

def decrypt_password(key, encrypted_text):
    fernet = Fernet(base64.urlsafe_b64encode(key))
    return fernet.decrypt(encrypted_text.encode()).decode()

def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for i in range(length))

# ---------- Authentication ----------
def setup_master_password():
    if os.path.exists(MASTER_FILE):
        return
    master = input("Set a new master password: ")
    hashed = hashlib.sha256(master.encode()).hexdigest()
    with open(MASTER_FILE, "w") as f:
        f.write(hashed)
    print("Master password set successfully!")

def verify_master_password():
    master = input("Enter master password: ")
    with open(MASTER_FILE, "r") as f:
        saved_hash = f.read()
    return hashlib.sha256(master.encode()).hexdigest() == saved_hash, master

# ---------- CRUD Operations ----------
def add_credential(key):
    website = input("Website/App Name: ")
    username = input("Username/Email: ")
    password = input("Password (leave blank to auto-generate): ")
    if not password:
        password = generate_strong_password()
        print(f"Generated Password: {password}")
    enc_pass = encrypt_password(key, password)

    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT INTO credentials (website, username, password) VALUES (?, ?, ?)", 
                (website, username, enc_pass))
    conn.commit()
    conn.close()
    print("Credential saved successfully!")

def view_credentials(key):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT website, username, password FROM credentials")
    for row in cur.fetchall():
        dec_pass = decrypt_password(key, row[2])
        print(f"Website: {row[0]}, Username: {row[1]}, Password: {dec_pass}")
    conn.close()

# ---------- Main Program ----------
def main():
    create_db()
    setup_master_password()
    verified, master_password = verify_master_password()
    if not verified:
        print("Access Denied!")
        return

    key = get_key(master_password)

    while True:
        print("\n1. Add Credential\n2. View Credentials\n3. Generate Strong Password\n4. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            add_credential(key)
        elif choice == "2":
            view_credentials(key)
        elif choice == "3":
            print("Generated:", generate_strong_password())
        elif choice == "4":
            print("Exiting... Stay secure!")
            break
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()
