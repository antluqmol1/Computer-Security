from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
import socket
import argparse
import time

# Setup command-line argument parsing
parser = argparse.ArgumentParser(description='File Transfer Client')
parser.add_argument('--host', default='localhost', help='Hostname or IP address of the server')
parser.add_argument('--port', type=int, default=12345, help='TCP port number on which the server is listening')
parser.add_argument('--dest', required=True, help='Destination file path to write the received file')
args = parser.parse_args()

# TCP client socket setup
print("Connecting to the server...")
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((args.host, args.port))   # Connect to the server

# Measuring time
start_time = time.time()

# Receive server's public key
print("Receiving server's public key...")
server_public_key = client_socket.recv(2048)
rsa_key = RSA.import_key(server_public_key)     # Import server's public RSA key

# Generate random AES key for symmetric encryption
print("Generating and encrypting AES key...")
aes_key = get_random_bytes(16)

# Encrypt AES key with server's public RSA key using PKCS1_OAEP padding
cipher_rsa = PKCS1_OAEP.new(rsa_key)
encrypted_aes_key = cipher_rsa.encrypt(aes_key)

# Send the encrypted AES key to the server
print("Sending encrypted AES key to the server...")
client_socket.send(encrypted_aes_key)

def recv_data(conn):
    data_length_bytes = conn.recv(4)
    if len(data_length_bytes) < 4:
        raise Exception("Failed to receive the full length prefix.")
    data_length = int.from_bytes(data_length_bytes, 'big')
    
    # Ensure the full data is read
    data = bytes()
    while len(data) < data_length:
        packet = conn.recv(data_length - len(data))
        if not packet:
            raise Exception("Connection closed before all data was received")
        data += packet
    return data

# Receive encrypted file
print("Receiving encrypted file...")
nonce = recv_data(client_socket)  # AES nonce for decryption
# print(f"nonce: {nonce}")
tag = recv_data(client_socket)    # Integrity tag for verifying the encrypted data
# print(f"tag: {tag}")
ciphertext = recv_data(client_socket)   # Encrypted file data
# print(f"Ciphertext: {ciphertext}")

# Decrypt file
print("Decrypting file...")
cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)   # Decrypt data and verify integrity with tag
# print(f"plaintext original: {plaintext}")

# File decripted, end of measuring time
end_time = time.time()
print(f"File receive and decrypt time: {end_time - start_time} seconds.")

# Save decrypted file data to a file
with open(args.dest, 'wb') as file:
    file.write(plaintext)
print(f"File decrypted and saved as {args.dest}")
client_socket.close()
