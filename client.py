import base64
import rsa
import requests
import aes_encryption as aes

# Define host and port
HOST, PORT = "localhost", 8080
# Define password for AES encryption
password = "This is a password to encrypt message".encode()

# Load public key from PEM file
with open("server_public.pem", "rb") as f:
    # Load public key from binary file and store in publicKey variable
    publicKey = rsa.PublicKey.load_pkcs1(f.read())
    print(publicKey)

# Load private key from PEM file
with open("client_private.pem", "rb") as f:
    # Load private key from binary file and store in privateKey variable
    privateKey = rsa.PrivateKey.load_pkcs1(f.read())

# Define function for sending a GET request to the server
def getKey():
    # Send GET request to the server
    r = requests.get("http://{}:{}".format(HOST, PORT))
    # Print response of GET request
    print("GET request response:", r.json())

# Define function for sending a POST request to the server with encrypted message and key
def sendMessage():
    # Get message input from user
    message = input("Enter message to send : ")
    # Encrypt message using AES encryption
    encryptMessage = aes.encrypt_message(message.encode(), password)
    # Encrypt password using RSA encryption
    encryptKey = rsa.encrypt(password, publicKey) 
    # Encode encrypted message and key into base64 string format
    encoded_data = base64.b64encode(encryptMessage).decode('utf-8')
    encoded_key = base64.b64encode(encryptKey).decode('utf-8')
    # Define header for POST request
    headers = {'Content-Type': 'application/json'}
    # Define payload with encoded message and key
    payload = {"data": encoded_data, "key": encoded_key}
    # Send POST request to the server with header and payload
    r = requests.post("http://{}:{}".format(HOST, PORT), headers=headers, json=payload)
    # Print response of POST request
    print("POST request response:")
    print(r.status_code)
    print(r.text)

# Continuously ask user for input and call sendMessage() if choice is 1, exit if choice is q
while True:
    choice = input("Enter 1 to send message (q to quit): ")
    if choice == 'q':
        break
    if choice == '1':
        sendMessage()
