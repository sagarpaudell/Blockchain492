# Secure Communication between Client and Server using RSA and AES encryption

The program is designed to securely transfer data between a client and a server. The goal is to ensure that the data transmitted between the client and server is protected against unauthorized access and tampering. The data is encrypted using AES encryption and the AES key is encrypted using RSA encryption.

## Setting up the program
To run the program, the following steps must be taken:

1.  Generate a private and public RSA key pair for both the client and the server.
       
        python generateKeys.py
2.  Share the public RSA key.
3. Run the server.py script on one terminal.

        python server.py
4. Run the client.py script on the separate terminal.
   
        python client.py

The client and server can then exchange encrypted data using the secure RSA and AES encryption. The program uses the rsa and aes_encryption libraries to handle the encryption and decryption.
