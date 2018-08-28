from flask import jsonify,request
from app import app
from flask import Flask, abort
from .getRandom import getRandom #For Random Number
from .keyGen import keyGenPair #For Key Generation
from .cryptoGen import RSA_EncryptData,RSA_DecryptData,EncryptData,DecryptData,hash_msg,gencert_content
import base64,os



@app.route('/')
@app.route('/index')
def index():
    return "<h1>Crypto-Engine </h1>"


'''API to generate secure strong random numbers (size in bits).
Two formats are provided. 'integer': gives a integer random number;
'binary': gives a random number as a binary base64 encoded.'''
@app.route('/api/v1.0/genToken/<int:size>/<string:format>',methods=['GET'])
@app.route('/api/v1.0/genToken/<int:size>',defaults={'format':'binary'},methods=['GET'])
def genToken(size,format):

    #Change bits to bytes
    size=int(size/8)
    if format.upper() == 'INTEGER':
        token=getRandom(size=size)
    else:
        token=os.urandom(size)
        token= base64.b64encode(token)
        token=token.decode()

    '''Return: the size(Bytes) of the number generated, 
    plus the random token in the format desired.'''
    data={'size':size,'token':token,'format':format.lower()}
    return jsonify(data),200


'''API for generation of public-key keypair.
Algorithm supported: RSA, ECDSA ; Size Key(bits) <2048 and 4096>.
This API, gives the option to specify the desired encoding of the key generated.
'Eprivate' and 'Epublic' are used for that purpose. If the encoding for the keys is not specified,
then the system defaults to: private(PEM), public (SSH). The output of a successful results,
corresponds to the result of the operation ('1') and the keypair. if the operation is not OK,
the result will evaluate to '0' and a status or reason will be provided.
To check the security constraints implemented by this API, please see config.py'''

@app.route('/api/v1.0/genKey/<string:algorithm>/<int:keySize>/<string:Eprivate>/<string:Epublic>',methods=['GET'])
@app.route('/api/v1.0/genKey/<string:algorithm>/<int:keySize>',defaults={'Eprivate':'PEM','Epublic':'SSH'},methods=['GET'])

def genKey(algorithm,keySize,Eprivate,Epublic):

    #Call keyGen method to obtain the result from request
    result,private_key,public_key,status = keyGenPair(algorithm, keySize,Eprivate,Epublic)

    if not result:
        data={'result':0,'status':status}
        return jsonify(data),200

    else:
        data={'result':1,'keypair':{'private_key':{'key':base64.b64encode(private_key).decode(),'encoding':Eprivate},'public_key':{'key':base64.b64encode(public_key).decode(),'encoding':Epublic}}}
        return jsonify(data),200

'''API for Symmetric Encryption. For a successful POST request, a caller must provide
  the private key, the plain text, the algorithm with the chosen mode and a random number used
  by the algorithm, this random number has to be saved by the caller to use it later when decrypting'''
@app.route('/api/v1.0/encryptdata', methods=['POST'])
def encryptdata():

    # Check if the request is properly formatted
    if not request.json or not all (k in request.json for k in ('key','plaintext','algorithm','mode','random')):
        abort(400)

    '''Parsing JSON parameters from POST request
    plain text is sent as string (base64 encoded)
    rest of parameters are sent as simple strings.'''

    json_dict=request.get_json()

    #Parameters
    key=json_dict['key']
    plaintext=json_dict['plaintext']
    algorithm=json_dict['algorithm']
    mode=json_dict['mode']
    random=json_dict['random']


    '''Call the EncryptData for symmetric encryption.
    this method will return the result of the operation 
    and the resultant ciphertext.'''
    result,ciphertext,status=EncryptData(base64.b64decode(plaintext.encode()),base64.b64decode(key.encode()),algorithm,mode,base64.b64decode(random.encode()))

    if result:
        #Format the response.
        ciphertext=base64.b64encode(ciphertext).decode()
        data={'result':1,'ciphertext':ciphertext}
        return jsonify(data),201
    else:
        data={'result':0, 'status':status}
        return jsonify(data),201

'''API for Symmetric Cipher Decryption'''
@app.route('/api/v1.0/decryptdata', methods=['POST'])
def decryptdata():

    # Check if the request is properly formatted
    if not request.json or not all (k in request.json for k in ('key','ciphertext','algorithm','mode','random')):
        abort(400)

    '''Parsing JSON parameters from POST request
    ciphertext,key are received as string (base64 encoded)
    rest of parameters are sent as simple strings.'''
    json_dict=request.get_json()

    #Parameters
    key=json_dict['key']
    ciphertext=json_dict['ciphertext']
    algorithm=json_dict['algorithm']
    mode=json_dict['mode']
    random=json_dict['random']

    '''Call the EncryptData for symmetric encryption.
    this method will return the result of the operation 
    and the resultant ciphertext.'''
    result,plaintext,status=DecryptData(base64.b64decode(ciphertext.encode()),base64.b64decode(key.encode()),
                                 algorithm,mode,base64.b64decode(random.encode()))


    if result:
        #Format the response.
        plaintext=base64.b64encode(plaintext).decode()
        data={'result':1,'plaintext':plaintext}
        return jsonify(data),201
    else:
        data={'result':0, 'status':status}
        return jsonify(data),201


''' API for Asymmetric encryption <Algorithms supported: RSA>
with key_size in (2048,4096)'''
@app.route('/api/v1.0/rsaencryptdata',methods=['POST'])
def rsaencryptdata():

    #Check if the request is probably formatted.
    if not request.json or not all (k in request.json for k in ('key','plaintext','algorithm')):
        abort(400)

    #getting the JSON parameters from POST request
    json_dict=request.get_json()
    key=json_dict['key']
    plaintext=json_dict['plaintext']
    algorithm=json_dict['algorithm']

    #Proceed to encrypt the provided text plain using 'key'
    result,cipher_text,status=RSA_EncryptData(base64.b64decode(plaintext.encode()),base64.b64decode(key.encode()),algorithm)

    if not result:
        data={'result':0, 'status':status}
    else:
        data={'result':1, 'ciphertext':cipher_text}

    return jsonify(data),201

''' API for Asymmetric encryption <Algorithms supported: RSA>
with key_size in (2048,4096)'''
@app.route('/api/v1.0/rsadecryptdata', methods=['POST'])
def rsadecryptdata():

    #Check if the request is probably formatted.
    if not request.json or not all (k in request.json for k in ('key','ciphertext','algorithm')):
        abort(400)

    #getting the JSON parameters from POST request
    json_dict=request.get_json()
    key=json_dict['key']
    ciphertext=json_dict['ciphertext']
    algorithm=json_dict['algorithm']

    #proceed to decrypt the provided cipher text using private key
    result,plain_text,status=RSA_DecryptData(base64.b64decode(ciphertext.encode()),
                                             base64.b64decode(key.encode()),
                                             algorithm)

    if not result:
        data={'result':0,'status':status}
    else:
        data={'result':"OK", 'plaintext':plain_text,'algorithm':algorithm}
    return jsonify(data),201



#3. API for hashing messages
@app.route('/api/v1.0/genHash',methods=['POST'])
def genHash():
    #Check if the request is properly formatted.
    if not request.json or not all (k in request.json for k in ('message','algorithm')):
        abort(400)

    #getting the JSON parameters from POST request
    json_dict=request.get_json()
    message=json_dict['message']
    algorithm=json_dict['algorithm']

    #Decode message
    message=base64.b64decode(message.encode())

    #Handle case insensitive for algorithm
    algorithm=algorithm.upper()

    #Get Digest for message
    result,digest,status=hash_msg(message=message,algorithm=algorithm)

    if not result:
        data ={'result':0,'status':status}
    else:
        data={'result':1,'digest':digest}

    return jsonify(data),201


@app.route('/api/v1.0/genCert',methods=['POST'])
def genCert():

    #Initial Checks
    #Check if the request is properly formatted.
    if not request.json or not all (k in request.json for k in ('x509request','private_key','subject')):
        abort(400)

    #getting the JSON parameters from POST request
    json_dict=request.get_json()
    x509request=json_dict['x509request']
    private_key=json_dict['private_key']
    subject=json_dict['subject']

    #Check the fields from subject
    if not all (l in subject for l in ('country','state','locality','organization','common')):
        abort(400)

    #Decode Key from JSON request
    private_key=base64.b64decode(private_key.encode())


    result, x509content, status = gencert_content(subject,x509request,private_key)

    if not result:
        data={'result':0,'status':status}
    else:
        data={'result':1,'x509content':x509content.decode(),'type':x509request}

    return jsonify(data),201




