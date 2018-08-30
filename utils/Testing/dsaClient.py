import base64,requests,sys

def file_parser(file,encode=True):
    try:
        with open(file, 'rb') as f:
            filecontent=f.read()

            if encode:
                dataEncoded = base64.b64encode(filecontent)
                dataDecoded = dataEncoded.decode()
                return dataDecoded
        return filecontent
    except IOError:
        return False


if len(sys.argv)!=4:
    print("Incorrect number of arguments:<message><algorithm><Key_size>")
    sys.exit(1)

#Get the input parameters
dsa_url="http://127.0.0.1:5000/api/v1.0/genSignature"
message=file_parser(sys.argv[1])
algorithm=sys.argv[2]
#print(message)

'''Construct 'data' to be sent in a POST request'''
#1. A key is needed, so call the appropriate Key API for generating a key-pair

key_size=sys.argv[3]
url="http://127.0.0.1:5000/api/v1.0/genKey"
myurl=url+"/"+algorithm+"/"+key_size

r=requests.get(myurl)
if r.status_code == 200:
    json_dict=r.json()
    if json_dict['result']:
        key_pair=json_dict['keypair']
        private_key=key_pair.get('private_key').get('key')
        public_key=key_pair.get('public_key').get('key')
    else:
        print("Error:{}".format(json_dict['status']))
        exit(1)
else:
    print("Error HTTP {}".format(r.status_code))
    exit(1)

#2. Get Signature

#Build POST to send DSA
data={'message':message,'private_key':private_key,
      'algorithm':algorithm}

#Now, send the port using 'cert_url' & 'data'
dsa_req=requests.post(dsa_url,json=data)
dsa_json=dsa_req.json()


if dsa_req.status_code !=201:
    print("The status of the request is {}".format(dsa_req.status_code))
else:
    if not dsa_json['result']:
        print("The request return an error: {}".format(dsa_json['status']))
    else:
        #get signature:
        signature=dsa_json['signature']

        #print the result
        print("The digital signature:")
        print("*"*45)
        print(base64.b64decode(signature.encode()))

# Verification of signature:
veri_url="http://127.0.0.1:5000/api/v1.0/veriSignature"

#Build the POST request
data={'signature':signature,'message':message,
      'algorithm':algorithm,'public_key':public_key}

#Now, send the POST request
dsa_verf=requests.post(veri_url,json=data)
dsa_verf_json=dsa_verf.json()

if dsa_verf.status_code !=201:
    print("The status of the request is {}".format(dsa_verf.status_code))
else:
    if not dsa_verf_json['result']:
        print("The request return an error: {}".format(dsa_verf_json['status']))
    else:
        #get the result:
        validation=dsa_verf_json['status']

        #print the result
        print("The digital signature verification:")
        print("*"*45)
        print(validation)













