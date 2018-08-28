import base64,requests,sys

if len(sys.argv)!=4:
    print("Incorrect number of arguments:<X509RequestType><algorithmForKey><Key_size>")
    sys.exit(1)

#Get the input parameters
cert_url="http://127.0.0.1:5000/api/v1.0/genCert"
x509request=sys.argv[1]

'''Construct 'data' to be sent in a POST request'''
#1. A key is needed, so call the appropriate Key API for generating a key-pair

algorithm=sys.argv[2]
key_size=sys.argv[3]
url="http://127.0.0.1:5000/api/v1.0/genKey"
myurl=url+"/"+algorithm+"/"+key_size

r=requests.get(myurl)
if r.status_code == 200:
    json_dict=r.json()
    if json_dict['result']:
        key_pair=json_dict['keypair']
        private_key=key_pair.get('private_key').get('key')
    else:
        print("Error:{}".format(json_dict['status']))
        exit(1)
else:
    print("Error HTTP {}".format(r.status_code))
    exit(1)

#2. Build the subject of the x509 request

subject={'country':'SW','state':'Skane','locality':'Lund',
         'organization':"Rise",'common':"test"}

#Build POST to send x509request
data={'x509request':x509request,'private_key':private_key,
      'subject':subject}

#Now, send the port using 'cert_url' & 'data'
cert_req=requests.post(cert_url,json=data)
cert_json=cert_req.json()


if cert_req.status_code !=201:
    print("The status of the request is {}".format(cert_req.status_code))
else:
    if not cert_json['result']:
        print("The request return an error: {}".format(cert_json['status']))
    else:
        #get the content from the x509 request:
        x509content=cert_json['x509content']

        #print the result
        print("The X509 content for the request {}:".format(x509request))
        print("*"*45)
        print(base64.b64decode(x509content.encode()).decode())















