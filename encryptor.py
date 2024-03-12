# Devadutta Ghat, 2024
import os
import json
import argparse
import qrcode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import serialization
from string import Template

def generate_salt(length):
    return os.urandom(length)

def base64_to_buffer(base64_str):
    return b64decode(base64_str)

def derive_key(password, salt, kdf, iterations, hash, cipher, key_length):
    if hash == 'SHA-256':
        hash_function = hashes.SHA256()
    else:
        raise ValueError('Unsupported hash type')

    kdf = PBKDF2HMAC(
        algorithm=hash_function,
        length=key_length // 8,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )

    return kdf.derive(password.encode())

def encrypt_text(password, password_hint, text):
    salt = generate_salt(16)
    iv = os.urandom(12)  # 96 bits for AES-GCM
    key = derive_key(password, salt, 'PBKDF2', 100000, 'SHA-256', 'AES-GCM', 256)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    encrypted_data = encryptor.update(text.encode()) + encryptor.finalize()

    return json.dumps({
        'version': '1',
        'cipher': 'AES-GCM',
        'tagLength': 128,
        'textEncoding': 'utf-8',
        'ciphertextEncoding': 'base64',
        'kdf': {'name': 'PBKDF2', 'iterations': 100000, 'hash': 'SHA-256', 'length': 256},
        'passwordHint': password_hint,
        'salt': b64encode(salt).decode('utf-8'),
        'iv': b64encode(iv).decode('utf-8'),
        'ciphertext': b64encode(encrypted_data + encryptor.tag).decode('utf-8'),
    }, indent=2)

def decrypt_text(password, encrypted_data_json):
    encrypted_data = json.loads(encrypted_data_json)
    salt = base64_to_buffer(encrypted_data['salt'])
    iv = base64_to_buffer(encrypted_data['iv'])
    ciphertext_and_tag = base64_to_buffer(encrypted_data['ciphertext'])
    ciphertext, tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]

    key = derive_key(password, salt, encrypted_data['kdf']['name'], encrypted_data['kdf']['iterations'], encrypted_data['kdf']['hash'], encrypted_data['cipher'], encrypted_data['kdf']['length'])

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()

def save_qr_code(data, filename):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)

html_template = Template('''
<!DOCTYPE html>
<html>
<meta charset="UTF-8">
<head>
    <title>Encrypted Data</title>
    <style>
        body {
            font-family: monospace;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        .qr-code {
            text-align: center;
        }
        .qr-code img {
            width: 400px;
            height: 400px;
        }
        .encrypted-data {
            margin-top: 20px;
            padding: 20px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        .encrypted-data pre {   
            white-space: pre-wrap;       
            overflow-wrap: break-word;
        }
        @media print {
            .pagebreak { page-break-before: always; } /* page-break-after works, as well */
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>$header</h1>
        <div class="qr-code">
            <!-- <img src="data:image/png;base64,qr_code" alt="QR Code"> -->
            <img src="$qr_image" alt="QR Code">
        </div>
        <div class="pagebreak"></div>
        <div class="encrypted-data">
            <pre>$encrypted_data</pre>
        </div>
    </div>
</body>
</html>
''')

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt a message.')
    parser.add_argument('-e','--encrypt', action='store_true', help='Encrypt a message')
    parser.add_argument('-d','--decrypt', action='store_true', help='Decrypt a message')
    parser.add_argument('-p', '--password', type=str, required=False, help='Password for encryption/decryption')
    parser.add_argument('-t','--text', type=str, help='Text to encrypt')
    parser.add_argument('-f','--file', type=str, help='File containing text to encrypt or decrypt')
    parser.add_argument('--header', type=str, help='Header for the document')
    
    parser.add_argument('--password-hint', type=str, help='Password hint for encryption')
    parser.add_argument('--qr', action='store_true', help='Save output as QR code (only for encryption)')
    args = parser.parse_args()
    
    if not (args.encrypt or args.decrypt):
        print("need to specify --encrypt or --decrypt. --help for more information.")
        exit(1)
    
    if args.file:
        with open(args.file, 'r') as file:
            args.text = file.read()
            
    if not args.password:
        # read .password file
        try:
            with open('.password', 'r') as file:
                args.password = file.read().strip()
        except FileNotFoundError:
            args.password = input("Enter password: ")

    if args.encrypt:
        if not args.text:
            args.text = input("Enter text to encrypt: ")
            
        encrypted_data = encrypt_text(args.password, args.password_hint, args.text)
        print("Encrypted data:", encrypted_data)
            
        if args.qr:
            save_qr_code(encrypted_data, 'encrypted_qr.png')
            print("QR code saved as encrypted_qr.png")
            #save html file
            with open('encrypted_data.html', 'w') as file:
                html = html_template.substitute({"encrypted_data":encrypted_data, "qr_image":'encrypted_qr.png',"header":args.header if args.header else "Encrypted Data"})
                file.write(html)
                print("HTML file saved as encrypted_data.html")
                    
    elif args.decrypt and args.file:
        with open(args.file, 'r') as file:
            encrypted_data_json = file.read()
        decrypted_data = decrypt_text(args.password, encrypted_data_json)
        print("Decrypted data:", decrypted_data.decode('utf-8'))
    else:
        print("Invalid operation. Use --help for more information.")

if __name__ == "__main__":
    main()
