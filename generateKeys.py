import rsa

def generateKeys(node):
    # Generate new RSA keys
    publicKey, privateKey = rsa.newkeys(512)

    # Write public key to PEM file
    with open(node+"public.pem", "wb") as f:
        f.write(rsa.PublicKey.save_pkcs1(publicKey))

    # Write private key to PEM file
    with open(node+"private.pem", "wb") as f:
        f.write(rsa.PrivateKey.save_pkcs1(privateKey))

    # # Load public key from PEM file
    # with open("public.pem", "rb") as f:
    #     publicKey = rsa.PublicKey.load_pkcs1(f.read())

    # # Load private key from PEM file
    # with open("private.pem", "rb") as f:
    #     privateKey = rsa.PrivateKey.load_pkcs1(f.read())

if __name__ == '__main__':
    choice = input('Enter preferred node')
    generateKeys(choice)