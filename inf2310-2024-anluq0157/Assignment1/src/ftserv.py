from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
import socket
import argparse
import time

# Setup command-line argument parsing
parser = argparse.ArgumentParser(description='File Transfer Server')
parser.add_argument('--file', required=True, help='Path to the file to serve')
parser.add_argument('--port', type=int, default=12345, help='TCP port number to listen on')
args = parser.parse_args()

# Generate RSA keys
print("Generating RSA keys...")
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# TCP server socket setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = ''  # Server hostname or IP address, Link to all interfaces
server_socket.bind((host, args.port))    # Link socket to the address and port
server_socket.listen(1)             # Listen incoming connections (1 = number of unaccepted connections before refusing new ones)
print(f"Server listening on port {args.port}")

def send_data(conn, data):
    conn.send(len(data).to_bytes(4, 'big'))
    conn.send(data)

def encrypt_and_send_file(conn, aes_key, file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)     # Create a new AES cipher in EAX mode for encryption
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)     # Encrypt file data and get ciphertext, tag for integrity
    # Send the AES cipher nonce, integrity tag, and the encrypted file data to the client
    # conn represents a socket connection between the server and a client
    send_data(conn, cipher_aes.nonce)
    send_data(conn, tag)
    send_data(conn, ciphertext)

# Main loop to accept connections
while True:
    conn, address = server_socket.accept()      # Accept new connection
    print(f"Connected to {address}")
    
    # Measuring time
    start_time = time.time()
    
    # Send public RSA key to the client
    print("Sending public RSA key to the client...")
    conn.sendall(public_key)

    # Receive the AES key encrypted with the server's public RSA key
    print("Receiving encrypted AES key from the client...")
    encrypted_aes_key = conn.recv(256)  # 256 = RSA Key size
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(private_key))    # Import private RSA Key for decryption
    print("Decrypting the AES key...")
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)     # Decrypt AES Key

    # Specify the file to serve
    #file_path = './plaintext.txt'  # Change as needed
    print(f"Encrypting and sending the file: {args.file}")
    encrypt_and_send_file(conn, aes_key, args.file) # Encrypt and send the file

    # File sent, end of measuring time
    end_time = time.time()
    print(f"File transfer time: {end_time - start_time} seconds.")
    print("File sent. Closing connection.")
    conn.close()
