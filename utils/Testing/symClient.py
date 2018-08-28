# Simple client to test API Crypto Functionality For Symmetric Encryption Decryption.
import sys
import base64, requests

def file_parser(file, encode=True):
    try:
        with open(file, 'rb') as f:
            filecontent = f.read()
            # print(filecontent)
            if encode:
                dataEncoded = base64.b64encode(filecontent)
                dataDecoded = dataEncoded.decode()
                return dataDecoded
        return filecontent
    except IOError:
        return False


if len(sys.argv) != 6:
    print(
        "Incorrect number of arguments: <Key_size> <Algorithm><token_size><Mode> <Plain/Cipher Text>")
    sys.exit(1)

# Getting input parameters
key_size = sys.argv[1]
algorithm = sys.argv[2]
token_size= sys.argv[3]
mode = sys.argv[4]
text = file_parser(sys.argv[5])

if not text:
    print("Plain-text does not exist in the path provided.")
    sys.exit(1)

try:

    ree = requests.get("http://127.0.0.1:5000/api/v1.0/genToken/" + key_size)
    ree1 = ree.json()
    key = ree1['token']

    token_request = requests.get("http://127.0.0.1:5000/api/v1.0/genToken/"+token_size)
    token_parameters = token_request.json()
    random = token_parameters['token']

    data = {'key': key, 'plaintext': text, 'algorithm': algorithm, 'mode': mode, 'random': random}
    r = requests.post("http://127.0.0.1:5000/api/v1.0/encryptdata", json=data)
    if r.status_code == 201:
        json_dict = r.json()
        result = json_dict['result']

        if result:
            cipher = json_dict['ciphertext']
            print("The cipher is: ")
            print("*"*45)
            print("{}".format(cipher))
            print("")

            ################################# Decryption Test ###################################
            #
            #######################################

            token_request1 = requests.get("http://127.0.0.1:5000/api/v1.0/genToken/" + token_size)
            token_parameters1 = token_request1.json()
            random1 = token_parameters1['token']

            data1 = {'ciphertext': cipher, 'key': key, 'algorithm': algorithm, 'mode': mode, 'random': random}
            r1 = requests.post("http://127.0.0.1:5000/api/v1.0/decryptdata", json=data1)

            if r1.status_code == 201:
                json_dict1 = r1.json()
                if json_dict1['result']:
                    print("The plaintext after decryption is: ")
                    print("*"*45)
                    print("{}".format(base64.b64decode(json_dict1['plaintext']).decode()))
                else:
                    print("The request failed due to: {}".format(json_dict1['status']))

        else:
            print("The request failed due to: {}".format(json_dict['status']))


except requests.exceptions.RequestException as error:
    print("There was an error: {}".format(error))
    sys.exit(1)







