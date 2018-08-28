from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64

#This block will encrypt the 'plain_text' with the public key provided.
#print(type(key_file)). Return a string from the base64 encoded byte string
def encrypt_data(message:bytes,pubkey:bytes):
    #Encryption
    public_key = serialization.load_ssh_public_key(pubkey, backend)
    ciphertext=public_key.encrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                algorithm=hashes.SHA1(),
                                                label=None))

    ciphertextEncoded=base64.b64encode(ciphertext)
    return ciphertextEncoded.decode()


#decrypts the 'cipher' using the 'privkey' supplied.
#cipher is assumed to be a base64-byte string and
#privkey is the key in byte string, return a string from the encoded byte string
def decrypt_data(cipher:bytes,privkey:bytes):
    private_key = serialization.load_pem_private_key(privkey, None, backend)
    text=private_key.decrypt(base64.b64decode(cipher),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                algorithm=hashes.SHA1(),
                                                label=None))
    return text.decode()



#testing the defined functions:


backend=default_backend()


path="id_rsa.pem"
with open(path,"rb") as key_f:
    key_file0=key_f.read()

with open("mypub.pem","rb") as key_f:
    key_b=key_f.read()

print("Private Key:")
print("")
print(key_file0.decode())

print("Public Key:")
print("")
print(key_b.decode())
print("**************")
cipher=encrypt_data(b"Honduras es un gran pais",key_b)
print(cipher)
print(" ")
text=decrypt_data(cipher.encode(),key_file0)
print(text)


