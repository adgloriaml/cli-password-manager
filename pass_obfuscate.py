#!/usr/bin/env python3

import os
import sys
import json
import hashlib
import gnupg
import subprocess

PASSWORD_STORE = os.path.expanduser("~/.password-store")
INDEX_FILE = os.path.join(PASSWORD_STORE, ".index.gpg")

gpg = gnupg.GPG()

def decrypt_index():
    if not os.path.exists(INDEX_FILE):
        return {}
    with open(INDEX_FILE, "rb") as f:
        decrypted = gpg.decrypt_file(f)
        if not decrypted.ok:
            print("Ошибка расшифровки индекса:", decrypted.status)
            sys.exit(1)
        return json.loads(str(decrypted))

def encrypt_index(data):
    json_data = json.dumps(data, indent=2)
    encrypted = gpg.encrypt(json_data, recipients=None, symmetric=True)
    if not encrypted.ok:
        print("Ошибка шифрования индекса:", encrypted.status)
        sys.exit(1)
    with open(INDEX_FILE, "wb") as f:
        f.write(encrypted.data)

def hash_name(name):
    # Используем sha256 от имени
    return hashlib.sha256(name.encode("utf-8")).hexdigest()

def pass_show(name):
    index = decrypt_index()
    hashed = index.get(name)
    if not hashed:
        print(f"Запись '{name}' не найдена")
        sys.exit(1)
    # Вызываем pass show hashed
    subprocess.run(["pass", "show", hashed])

def pass_insert(name):
    index = decrypt_index()
    hashed = hash_name(name)
    # Проверим, нет ли уже такого хеша
    if hashed in index.values():
        print(f"Запись с таким хешем уже существует")
        sys.exit(1)

    # Добавляем в индекс
    index[name] = hashed
    encrypt_index(index)

    # Вызываем pass insert hashed
    subprocess.run(["pass", "insert", hashed])

def pass_search(pattern):
    index = decrypt_index()
    for key in index.keys():
        if pattern in key:
            print(key)

def main():
    if len(sys.argv) < 3:
        print("Использование: pass_obfuscate.py <команда> <имя|паттерн>")
        print("Команды: show, insert, search")
        sys.exit(1)

    cmd = sys.argv[1]
    arg = sys.argv[2]

    if cmd == "show":
        pass_show(arg)
    elif cmd == "insert":
        pass_insert(arg)
    elif cmd == "search":
        pass_search(arg)
    else:
        print("Неизвестная команда")
        sys.exit(1)

if __name__ == "__main__":
    main()
