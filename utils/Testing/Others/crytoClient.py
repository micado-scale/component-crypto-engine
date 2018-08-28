# Simple client to test API Crypto Functionality.
import sys
import base64,requests,os

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


if len(sys.argv)!=7:
    print("Incorrect number of arguments: <url API> <Key_Type: Private/Public> <Key:Pem Formatted> <Algorithm> <Mode> <Plain/Cipher Text>")
    sys.exit(1)

#Getting input parameters
url=sys.argv[1]
key_type=sys.argv[2]
key=file_parser(sys.argv[3])
text=file_parser(sys.argv[6])
algorithm=sys.argv[4]
mode=sys.argv[5]

if not (key and text):
    print("Key or text does not exist in the path provided.")
    sys.exit(1)


if key_type.upper()=='PUBLIC':
    #Decrypt---> Call the API
    try:
        data={'key':key, 'plaintext':text, 'algorithm':algorithm}
        r=requests.post(url,json=data)

        #Check status of request
        if r.status_code==201:
            json_dict=r.json()

            if not json_dict['result']:
                print("Error the request failed {}".format(json_dict['status']))
            else:
                cipher_text = json_dict['ciphertext']

            #print base64-byte encoded string.
                print(cipher_text)
            #print("The length is {}".format(len(cipher_text)))

        else:
            print("Crypto-Engine: Error {}".format(r.status_code))
            sys.exit(1)

    except requests.exceptions.RequestException as error:
        print("Error: Please verify url, wrong JSON request")
        sys.exit(1)

elif key_type.upper()=='PRIVATE':
    try:
        text = file_parser(sys.argv[6],False)
        #print("The length is {}".format(len(text)))
        textDecode=text.decode()
        print('The passed argument is: {}'.format(algorithm))
        data={'key':key,'ciphertext':textDecode, 'algorithm':algorithm}

        r=requests.post(url,json=data)

        #check status of request
        if r.status_code==201:
            json_dict = r.json()
            if not json_dict['result']:
                print("Crypto_Engine: Error {}".format(json_dict['status']))
            else:
                plain_text=json_dict['plaintext']
                #print plaintext string
                print(plain_text,end="")

        else:
            print("Crypto-Engine: Error {}".format(r.status_code))
            sys.exit(1)
    except requests.exceptions.RequestException as error:
        print("error: Please verify url, wrong JSON request")
        sys.exit(1)

elif key_type.upper()=='SYMMETRIC':
    try:


        ree= requests.get("http://127.0.0.1:5000/api/v1.0/genToken/"+ key_size)
        ree1=ree.json()
        key=ree1['token']

        token_request = requests.get("http://127.0.0.1:5000/api/v1.0/genToken/"+token_size)
        token_parameters=token_request.json()
        random=token_parameters['token']

        data = {'key':key, 'plaintext': text, 'algorithm': algorithm,'mode': mode,'random':random}
        r = requests.post("http:127.0.0.1:5000/api/v1.0/encryptdata", json=data)
        if r.status_code==201:
            json_dict = r.json()
            result=json_dict['result']
            print("The result of the request is: {} and {}".format(r.status_code, result))
            if result:
                cipher=json_dict['ciphertext']
                print("The cipher is: {}".format(cipher))

                ################################# Decryption Test ###################################
                #use Another token
                #token_request = requests.get("http://127.0.0.1:5000/api/v1.0/genToken/16")
                #token_parameters = token_request.json()
                #random = token_parameters['token']
                #######################################

                data1={'ciphertext':cipher,'key':key,'algorithm': algorithm,'mode': mode,'random':random}
                r1 = requests.post("http://127.0.0.1:5000/api/v1.0/decryptdata",json=data1)
                print(r1.status_code)
                if r1.status_code == 201:
                    json_dict1=r1.json()
                    if json_dict1['result']:
                        print("The plain is {}".format(base64.b64decode(json_dict1['plaintext']).decode()))
                    else:
                        print("reason:{}".format(json_dict1['status']))


            else:
                print("reason:{}".format(json_dict['status']))



    except requests.exceptions.RequestException as error:
        print("Please check the HTTP request")
        sys.exit(1)



else:
    print('Crypto-Engine: Incorrect key type.')
    sys.exit(1)




