import socket
import base64


key = b'\x01\x02\x03\x04\x05\x06\x07\x08' 


def encrypt(data):
    # Convert the data to a byte array
    data_bytes = data.encode('ascii')

    # Encrypt the data using the XOR key
    encrypted_bytes = bytearray()
    for i, b in enumerate(data_bytes):
        encrypted_bytes.append(bytes([b])[0] ^ key[i % len(key)])

    # Return the encrypted data as a bytes object
    return encrypted_bytes

# Decrypt the data using the XOR operator and the key
def decrypt(data):
    # Convert the data to a byte array
    data_bytes = bytearray(data)

    # Decrypt the data using the XOR key
    decrypted_bytes = bytearray()
    for i, b in enumerate(data_bytes):
        decrypted_bytes.append(bytes([b])[0] ^ key[i % len(key)])

    # Return the decrypted data as a bytes object
    return decrypted_bytes

    
HOST = '0.0.0.0'
PORT = 4444

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.bind((HOST, PORT))


server_sock.listen()


client_sock, client_address = server_sock.accept()
print(f'Connected to {client_address[0]}:{client_address[1]}')

responseWasEmptyOrStart = 1


encrypted_message = client_sock.recv(1024)
responseWasEmpty =0
# Decrypt the message
message = decrypt(encrypted_message).decode("ascii")
print(f'Received: {message}')



while True:
    # Send an encrypted response to the client
    response = input('Enter a Command: ')
   
    if response:
        encrypted_response = encrypt(response)
        client_sock.send(encrypted_response)
        encrypted_message = client_sock.recv(1024)
        responseWasEmpty =0
        # Decrypt the message
        message = decrypt(encrypted_message).decode("ascii")
        message = base64.b64decode(message).decode("utf-8")
        print(f'Received: {message}')
    else:
        responseWasEmpty = 1
        continue


client_sock.close()
server_sock.close()
