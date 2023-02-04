# Import the necessary libraries
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import aes_encryption as aes
import rsa

# Load the public key from the PEM file
with open("client_public.pem", "rb") as f:
    publicKey = rsa.PublicKey.load_pkcs1(f.read())

# Load the private key from the PEM file
with open("server_private.pem", "rb") as f:
    privateKey = rsa.PrivateKey.load_pkcs1(f.read())

# Create the RequestHandler class to handle incoming requests
class RequestHandler(BaseHTTPRequestHandler):
    # Handle the GET request
    def do_GET(self):
        # Send a 200 OK response
        self.send_response(200)
        # Send the header with the content type as JSON
        self.send_header("Content-type", "application/json")
        # End the headers
        self.end_headers()
        # Prepare the response in JSON format
        response = {"message": "GET request received!"}
        # Write the response to the file
        self.wfile.write(json.dumps(response).encode("utf-8"))
 
    # Handle the POST request
    def do_POST(self):
        # Get the length of the incoming data
        content_length = int(self.headers["Content-Length"])
        # Read the incoming data
        post_data_str = self.rfile.read(content_length).decode("utf-8")
        # Load the incoming data as JSON
        post_data_json = json.loads(post_data_str)
        # Send a 200 OK response
        self.send_response(200)
        # Send the header with the content type as JSON
        self.send_header("Content-type", "application/json")
        # End the headers
        self.end_headers()
        # Prepare the response in JSON format
        response = {"message": "POST request received!", "data": post_data_str}
        # Get the encrypted message and key from the incoming data
        encryptedMessage = post_data_json["data"]
        encryptedKey = post_data_json["key"]
        # Print the incoming data for debugging purposes
        print(post_data_json)
        # Decode the encrypted message and key from base64
        decoded_data = base64.b64decode(encryptedMessage.encode('utf-8'))
        decoded_key = base64.b64decode(encryptedKey.encode('utf-8'))
        # Decrypt the AES key using RSA
        aes_key = rsa.decrypt(decoded_key, privateKey)
        # Decrypt the message using the AES key
        data = aes.decrypt_message(decoded_data, aes_key)
        # Print the decrypted message
        print('DATA SENT BY SERVER {}'.format(data))
        # Write the response to the file
        self.wfile.write(json.dumps(response).encode("utf-8"))

# Set the host and port for the server
HOST, PORT = "localhost", 8080
# Create the HTTPServer object
server = HTTPServer((HOST, PORT), RequestHandler)
print("Serving on {}:{}".format(HOST, PORT))
server.serve_forever()