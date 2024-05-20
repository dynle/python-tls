import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

# Constants for nonce and tag length of AES-GCM
NONCE_LENGTH = 16
TAG_LENGTH = 16


################ Handshake Phase ################

# Generate a 2048-bit RSA key pair
server_private_key = RSA.generate(2048)
server_public_key = server_private_key.publickey()

# Server setup (TCP/IP socket)
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 33333))
server_socket.listen(1)

print("Server is listening...")
while True:
    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    # Handshake - Send server's public key to the client
    conn.send(server_public_key.export_key())

    # Receive encrypted session key from the client
    encrypted_session_key = conn.recv(256)

    # Decrypt session key using RSA
    cipher_rsa = PKCS1_OAEP.new(server_private_key)
    session_key = cipher_rsa.decrypt(encrypted_session_key)


    ################ Data Transfer Phase ################
    '''
        * Continuously receive data from the client
        * Decrypt the data using AES-GCM with the session key
            - Use modern symmetric ciper: Advanced Encyption Standard (AES) (confidentiality)
            - Use block cipher mode: Galois/Counter Mode (GCM) (integrity)
        * If decryption fails or data integrity is compromised, print an error message
        * Encrypt a response using AES-GCM and send it to the client
        * Close the connection when the client disconnects
    '''
    # Communication
    try:
        while True:
            # Receive data from the client
            data = conn.recv(1024)
            if not data:
                break
            
            nonce = data[:NONCE_LENGTH]
            ciphertext = data[NONCE_LENGTH:-TAG_LENGTH]
            tag = data[-TAG_LENGTH:]
            
            # Decrypt data using AES-GCM
            cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            try:
                # Decrypt the data and verify its integrity by the tag
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                print(f"Received: {plaintext}\n")
            except ValueError:
                print("Decryption failed / Integrity checks failed (Data was tampered with)")

            # Encrypt response using AES-GCM
            response = b"Connection established from server."
            cipher = AES.new(session_key, AES.MODE_GCM)
            # Encrypt the response and generate a tag (for data integrity)
            ciphertext, tag = cipher.encrypt_and_digest(response)
            conn.send(cipher.nonce + ciphertext + tag)

    finally:
        conn.close()




