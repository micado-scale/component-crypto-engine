import sys,base64,requests

if len(sys.argv)!=3:
    print("Incorrect number of arguments: <Hash Algorithm> <Message>")
    sys.exit(1)

#Get the input variables
url="http://127.0.0.1:5000/api/v1.0/genHash"
algorithm=sys.argv[1]
message=sys.argv[2]


#Encode Message:
with open(message,"rb") as f:
    message=f.read()

message=base64.b64encode(message).decode()

try:
    data={'message':message,'algorithm':algorithm}
    r=requests.post(url,json=data)

    if r.status_code==201:
        json_dic=r.json()

        #Check the result:
        if json_dic['result']:
            #get the digest
            digest=json_dic['digest']
            print("The digest is: {}".format(digest))

        else:
            print("The hash can not be computed reason:{}".format(json_dic['status']))
    else:
        print("The request failed status code: {}".format(r.status_code))
except requests.exceptions.RequestException as error:
        print("HTTP failed: {}".format(error))
        sys.exit(1)



