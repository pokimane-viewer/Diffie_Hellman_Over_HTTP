import os
import base64
import sys
import requests
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
server_private_key = params.generate_private_key()
server_public_key = server_private_key.public_key()
session_keys = {}

@app.route('/diffie/handshake', methods=['POST'])
def handshake():
    data = request.get_json()
    client_public_bytes = base64.b64decode(data['public_key'])
    client_public_key = serialization.load_pem_public_key(client_public_bytes, backend=default_backend())
    shared_key = server_private_key.exchange(client_public_key)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'diffie-hellman', backend=default_backend())
    symmetric_key = hkdf.derive(shared_key)
    session_id = base64.b64encode(os.urandom(16)).decode('utf-8')
    session_keys[session_id] = symmetric_key
    server_public_bytes = server_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return jsonify({'public_key': base64.b64encode(server_public_bytes).decode('utf-8'), 'session_id': session_id})

@app.route('/diffie/message', methods=['POST'])
def message_endpoint():
    data = request.get_json()
    session_id = data.get('session_id')
    if session_id not in session_keys:
        return jsonify({'error': 'invalid session id'}), 400
    symmetric_key = session_keys.pop(session_id)
    iv = base64.b64decode(data['iv'])
    ciphertext = base64.b64decode(data['ciphertext'])
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return jsonify({'message': plaintext.decode('utf-8')})

def client_demo():
    params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    client_private_key = params.generate_private_key()
    client_public_key = client_private_key.public_key()
    client_public_bytes = client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    data = {'public_key': base64.b64encode(client_public_bytes).decode('utf-8')}
    r = requests.post('https://localhost:5000/diffie/handshake', json=data)
    response = r.json()
    server_public_bytes = base64.b64decode(response['public_key'])
    server_public_key = serialization.load_pem_public_key(server_public_bytes, backend=default_backend())
    session_id = response['session_id']
    shared_key = client_private_key.exchange(server_public_key)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'diffie-hellman', backend=default_backend())
    symmetric_key = hkdf.derive(shared_key)
    message = b"Attack at dawn"
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    data = {'session_id': session_id, 'iv': base64.b64encode(iv).decode('utf-8'), 'ciphertext': base64.b64encode(ciphertext).decode('utf-8')}
    r = requests.post('https://localhost:5000/diffie/message', json=data)
    print(r.json())

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'client':
        client_demo()
    else:
        app.run(ssl_context='adhoc')