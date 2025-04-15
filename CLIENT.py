import os
import base64
import requests
import threading
import logging
from tkinter import Tk, Text, Entry, Button, END
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
SERVER_URL = 'https://localhost:5000'

def perform_handshake():
    params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    client_private_key = params.generate_private_key()
    client_public_key = client_private_key.public_key()
    client_public_bytes = client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    handshake_data = {'public_key': base64.b64encode(client_public_bytes).decode('utf-8')}
    logging.debug("Performing handshake with server")
    r = requests.post(f'{SERVER_URL}/diffie/handshake', json=handshake_data, verify=False)
    response = r.json()
    server_public_bytes = base64.b64decode(response['public_key'])
    session_id = response['session_id']
    server_public_key = serialization.load_pem_public_key(server_public_bytes, backend=default_backend())
    shared_key = client_private_key.exchange(server_public_key)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'diffie-hellman', backend=default_backend())
    symmetric_key = hkdf.derive(shared_key)
    logging.debug(f"Handshake complete; session_id: {session_id}")
    return symmetric_key, session_id

def encrypt_message(symmetric_key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return iv, ciphertext

def send_secure_message(message):
    symmetric_key, session_id = perform_handshake()
    iv, ciphertext = encrypt_message(symmetric_key, message)
    payload = {
        'session_id': session_id,
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }
    logging.debug(f"Sending encrypted message: {payload}")
    r = requests.post(f'{SERVER_URL}/diffie/message', json=payload, verify=False)
    response = r.json()
    logging.debug(f"Server response: {response}")
    return response

class ChatClient:
    def __init__(self, master):
        self.master = master
        master.title("Secure Chat Client")
        self.chat_area = Text(master, state='disabled', wrap='word')
        self.chat_area.pack(expand=True, fill='both')
        self.entry = Entry(master)
        self.entry.pack(fill='x')
        self.send_button = Button(master, text="Send", command=self.send_message)
        self.send_button.pack()
        self.entry.bind("<Return>", lambda event: self.send_message())

    def send_message(self):
        message = self.entry.get().strip()
        if not message:
            return
        self.entry.delete(0, END)
        self.print_chat("You: " + message)
        threading.Thread(target=self.process_message, args=(message,), daemon=True).start()

    def process_message(self, message):
        try:
            response = send_secure_message(message)
            server_message = response.get('message', '')
            self.print_chat("Server: " + server_message)
        except Exception as e:
            logging.exception("Message processing error")
            self.print_chat("Error: " + str(e))

    def print_chat(self, text):
        self.chat_area.config(state='normal')
        self.chat_area.insert(END, text + "\n")
        self.chat_area.config(state='disabled')
        self.chat_area.see(END)

if __name__ == "__main__":
    root = Tk()
    ChatClient(root)
    root.mainloop()