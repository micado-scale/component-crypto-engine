# Simple client to test API Crypto Functionality.
import sys
import base64,requests

def file_parser(file,encode=True):
    try:
        with open(file, 'rb') as f:
            filecontent=f.read()
            #print(filecontent)
            if encode:
                dataEncoded = base64.b64encode(filecontent)
                dataDecoded = dataEncoded.decode()
                return dataDecoded
        return filecontent
    except IOError:
        return False


if len(sys.argv)!=4:
    print("Incorrect number of arguments: <Key_size> <Algorithm> <PlainText>")
    sys.exit(1)

#Getting input parameters
key_size=sys.argv[1]
algorithm=sys.argv[2]
text=file_parser(sys.argv[3])


if not text:
    print("plaintext does not exist in the path provided.")
    sys.exit(1)

#Generate the corresponding key pair:
url="http://127.0.0.1:5000/api/v1.0/genKey"
myurl=url+"/"+algorithm+"/"+key_size
url_encrypt="http://127.0.0.1:5000/api/v1.0/rsaencryptdata"
url_decrypt="http://127.0.0.1:5000/api/v1.0/rsadecryptdata"

r=requests.get(myurl)
if r.status_code == 200:
    json_dict=r.json()
    if json_dict['result']:
        key_pair=json_dict['keypair']
        private_key=key_pair.get('private_key').get('key')
        public_key = key_pair.get('public_key').get('key')
    else:
        print("Error:{}".format(json_dict['status']))
        exit(1)
else:
    print("Error HTTP {}".format(r.status_code))
    exit(1)


#Lets try encryption (Using public key)
try:
    data = {'key':public_key, 'plaintext': text, 'algorithm': algorithm}
    r = requests.post(url_encrypt, json=data)

    #Check status of request
    if r.status_code == 201:
        json_dict=r.json()

        if not json_dict['result']:
            print("Error the request failed {}".format(json_dict['status']))
            exit(1)
        else:
            cipher_text = json_dict['ciphertext']
            print("The cipher text:")
            print("*"*45)
            print(cipher_text)
            print("")

    else:
        print("Crypto-Engine: Error {}".format(r.status_code))
        sys.exit(1)

except requests.exceptions.RequestException as error:
    print("Error: Please verify url, wrong JSON request")
    sys.exit(1)

#print("Encryption complete...............")

# If Encryption is OK, Then lets try Decryption with private key
try:

    data={'key':private_key,'ciphertext':cipher_text, 'algorithm':algorithm}

    r=requests.post(url_decrypt,json=data)

    #check status of request
    if r.status_code==201:
        json_dict = r.json()
        if not json_dict['result']:
            print("Crypto_Engine: Error {}".format(json_dict['status']))
            exit(1)
        else:
            plain_text=json_dict['plaintext']
            print("The plain text(after decryption):")
            print("*" * 45)
            print(plain_text)
    else:
        print("Crypto-Engine: Error {}".format(r.status_code))
        sys.exit(1)

except requests.exceptions.RequestException as error:
    print("error: Please verify url, wrong JSON request")
    sys.exit(1)





