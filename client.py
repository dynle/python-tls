import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# Constants for nonce and tag length of AES-GCM
NONCE_LENGTH = 16
TAG_LENGTH = 16


################ Handshake Phase ################

# Client setup (TCP/IP socket)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client_socket.bind(('localhost', 33332))
client_socket.connect(('localhost', 33333))

# Handshake - Receive server's public key
server_public_key_data = client_socket.recv(2048)
server_public_key = RSA.import_key(server_public_key_data)

# Generate a 32-byte random session key and encrypt it with the server's public key using RSA
session_key = get_random_bytes(32)
cipher_rsa = PKCS1_OAEP.new(server_public_key)
encrypted_session_key = cipher_rsa.encrypt(session_key)
client_socket.send(encrypted_session_key)


################ Data Transfer Phase ################
'''
    * Encrypt a message with AES-GCM using the session key
        - Use modern symmetric ciper: Advanced Encyption Standard (AES) (confidentiality)
        - Use block cipher mode: Galois/Counter Mode (GCM) (integrity)
    * Send the nonce, ciphertext, and tag to the server
    * Receive a response from the server
    * Decrypt the response using AES-GCM and verify its integrity
    * Close the connection
'''
# Communication
# Encrypt data using AES-GCM
message = b"Connection established from client."
cipher = AES.new(session_key, AES.MODE_GCM)
# Encrypt the response and generate a tag (for data integrity)
ciphertext, tag = cipher.encrypt_and_digest(message)
client_socket.send(cipher.nonce + ciphertext + tag)

data = client_socket.recv(1024)
# Decrypt response using AES-GCM
nonce = data[:NONCE_LENGTH]
ciphertext = data[NONCE_LENGTH:-TAG_LENGTH]
tag = data[-TAG_LENGTH:]
cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
try:
    response = cipher.decrypt_and_verify(ciphertext, tag)
    print(f"Received: {response}\n")
except ValueError:
    print("Decryption failed / Integrity checks failed (Data was tampered with)")

client_socket.close()




