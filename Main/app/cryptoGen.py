from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64,datetime,os
from cryptography.hazmat.primitives import padding as sypadding #For symmetric padding
from cryptography import exceptions as crypto_exception
from cryptography import x509
from cryptography.x509.oid import NameOID
from .views import app


#default crypto library
backend=default_backend()

'''symmetric_check checks if the key size and algorithm
are compliant with the security system. It receives the 
'size_key' in bytes and the algorithm as input parameters.
It returns a tuple with the result of the check;
the algorithm name used by the crypto library and
the block size of the algorithm.'''
def symmetric_check(key,algorithm,mode,random):
    #Get the size key in bits
    size_key=int(8*len(key))

    #Get the size of 'random in bytes
    random_size=int(len(random))


    if algorithm.upper() in app.config['CRYPTOCONF'].keys():

        if mode.upper() in app.config['CRYPTOCONF'].get(algorithm).get('mode'):
            if random_size == app.config['CRYPTOCONF'].get(algorithm).get('blocksize'):
                #print(app.config['CRYPTOCONF'].get(algorithm).get('keysize'))
                if size_key in app.config['CRYPTOCONF'].get(algorithm).get('keysize'):

                    return (True,app.config['CRYPTOCONF'].get(algorithm).get('name'),
                            app.config['CRYPTOCONF'].get(algorithm).get('blocksize'),"OK")
                return (False,"","","Key size not supported")
            return (False,"","","The random number size is not valid for the algorithm selected.")
        return (False,"","","Mode not supported")

    return (False, " ","","Algorithm not supported")


'''paddingMsg: this function pads 'message'
to get a proper multiple of the protocol's
block size.'''
def paddingMsg(message:bytes,block_size):
    block_size = int(block_size * 8)
    try:
        padder = sypadding.PKCS7(block_size).padder()
        padded_data = padder.update(message)
        padded_data += padder.finalize()
        return padded_data
    except ValueError:
        return False

'''unpaddingMsg: This function unpads a message,
after decryption to get the correct plain text.'''
def unpaddingMsg(message:bytes,block_size):
    block_size =int(block_size*8)
    try:
        unpadder=sypadding.PKCS7(block_size).unpadder()
        data=unpadder.update(message)
        data += unpadder.finalize()
        return data
    except ValueError:
        return False

'''This function loads a key to the crypto engine
First tries to load the key assuming a PEM format,
 if not SSH or DER, if none work, then error is return.
 On Success this function returns a crypto object'''
def key_loader(key:bytes,type,password:bytes=None):

    #Create array of input arguments
    if type=='private':
        parameters=[key,password,backend]
    else:
        parameters=[key,backend]

    try:
        key=getattr(serialization,"load_pem_{}_key".format(type))(*parameters)
        result=True
    except ValueError:
        try:
            if type!='private':
                key = getattr(serialization, "load_ssh_{}_key".format(type))(*parameters)
                result=True
            else:
                key=""
                result=False
        except ValueError:
            try:
                key = getattr(serialization, "load_der_{}_key".format(type))(*parameters)
                result = True
            except ValueError:
                key = ""
                result = False

    return (result,key)

'''This function is used to load a private key, that will be used 
for signing Certificate; the private key of the CA (The crypto Engine,
is set as the CA)'''

def load_CA_Key(key_path):
    try:
        with open(key_path,"rb") as fh:
            CA_private_key=fh.read()
    except IOError:
        return (False,"","CA could not find private_key")

    result,CA_private_key = key_loader(CA_private_key,'private',None)

    if not result:
        return (False,"","CA could not load private Key")
    return (result,CA_private_key,"OK")

'''This function constructs either a subject or issuer
based on input parameters'''
def load_entity(parameters):
    try:
        entity = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, parameters.get('country')),
                               x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, parameters.get('state')),
                               x509.NameAttribute(NameOID.LOCALITY_NAME, parameters.get('locality')),
                               x509.NameAttribute(NameOID.ORGANIZATION_NAME,parameters.get('organization')),
                               x509.NameAttribute(NameOID.COMMON_NAME,parameters.get('common')), ])
    except (ValueError,TypeError) as error:
        return (False,"",str(error))

    return (True,entity,"OK")


'''These functions are meant for Asymmetric operations:
(RSA-Encryption) RSAEncryptData, (RSA-Decryption) RSADecryption'''
#This block will encrypt the 'plain_text' with the public key provided.
# encrypt_data returns a base64 encoded byte string
def RSA_EncryptData(message:bytes,pubkey:bytes,algorithm='RSA'):
    algorithm=algorithm.upper()
    #Check input parameters are compliant with the security of the engine
    #Key must be either
    if not algorithm=='RSA':
        return (False,"","Algorithm {} not supported".format(algorithm))

    #Load the supplied Public Key..
    result,public_key = key_loader(pubkey,'public')

    if not result:
        return (False,"","Public key cannot be loaded.")

    #Check key size
    if not public_key.key_size in app.config['ASYMCONF'].get(algorithm).get('keysize'):
        return (False,"","keysize {} bits not supported".format(public_key.key_size))


    #Encrypt the plaintext provided with the loaded public key.
    ciphertext=public_key.encrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                algorithm=hashes.SHA1(),
                                                label=None))

    #Encode the cipher text using base64-enconding
    ciphertextEncoded=base64.b64encode(ciphertext)

    #Format the just encoded byte cipher text to be sent
    #in a JSON response. (String-like field).
    return (True,ciphertextEncoded.decode(), "OK")


#decrypts the 'ciphertext' using the 'privkey' supplied.
#cipher is assumed to be a base64-byte string and
#privkey, private key serialized as a  byte string.
def RSA_DecryptData(cipher:bytes,privkey:bytes,algorithm='RSA'):
    algorithm=algorithm.upper()

    #Check input parameters are compliant with the security of the engine
    #Key must be either
    if not algorithm=='RSA':
        return (False,"","Algorithm {} not supported".format(algorithm))

    #Load the supplied  private .pem key
    result,private_key = key_loader(privkey,'private')

    if not result:
        return (False,"","Public key cannot be loaded.")

    #Check key size
    if not private_key.key_size in app.config['ASYMCONF'].get(algorithm).get('keysize') :
        return (False,"","keysize {} bits not supported".format(private_key.key_size))


    #Decryp the cipher text using the loaded private key
    text=private_key.decrypt(cipher,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                algorithm=hashes.SHA1(),
                                                label=None))

    #Format the just decrypted text to be sent as a plain string
    return (True,text.decode(),"OK")


'''These methods are meant for symmetric cryptography operations:
(Encryption): EncryptData, (Decryption): DecryptData'''

'''Symmetric Encryption'''
def EncryptData(message:bytes,key:bytes,algorithm,mode,random:bytes):
    #print("The key: {} and its length {}".format(key,len(key)))

    #Handle insensitive-case Algorithm and Mode names,
    algorithm=algorithm.upper()
    mode=mode.upper()

    #is the key size and algorithm compliant to the system
    #security requirements?
    result,algorithm_name,blockSize,status = symmetric_check(key=key,algorithm=algorithm,mode=mode,random=random)

    '''Check if algorithm, mode and key size are compliant.Security requirements
    are defined by the administrator'''
    if not result:
        return (False,"",status)

    #Create a random byte string of blockSize length
    #iv=os.urandom(blockSize)

    try:
        cipher = Cipher(getattr(algorithms,algorithm_name)(key),getattr(modes,mode)(random), backend=backend)

        #Creates a cypher context instance
        encryptor=cipher.encryptor()

        #Check if padding is required for given cipher mode.
        if app.config['CRYPTOCONF'].get(algorithm).get('mode').get(mode).get('pad'):
            #Padding 'message'
            #print("Crypto-Engine: padding is required for mode: {}".format(mode))
            message=paddingMsg(message,app.config['CRYPTOCONF'].get(algorithm).get('blocksize'))

        if not message:
            return (False,"","Encryption:Wrong pad due to wrong key!")

        #Encrypt and obtain the final result
        cipher_text=encryptor.update(message)+encryptor.finalize()
        #print("The type is equal to: {}".format(type(ct)))
        return (True,cipher_text,"OK")

    #Combination not supported in the crypto library (backend)
    except crypto_exception.UnsupportedAlgorithm:
        return (False,"","Unsupported Algorithm")


'''Symmetric Decryption'''
def DecryptData(cipher_text:bytes,key:bytes,algorithm,mode,random:bytes):
    algorithm =algorithm.upper()
    mode=mode.upper()

    #Check if 'algorithm' and 'mode' are allowed.
    result, algorithm_name, blockSize,status = symmetric_check(key=key, algorithm=algorithm, mode=mode,random=random)

    '''Check if algorithm, mode and key size are compliant.Security requirements
    are defined by the administrator'''
    if not result:
        return (False,"",status)

    '''Creation of a Cipher object using the passed parameters'''
    try:
        #Random corresponds to an IV or Nonce, depending on the Mode selected.
        cipher = Cipher(getattr(algorithms, algorithm_name)(key), getattr(modes, mode)(random), backend=backend)

        #Creates a cypher context instance
        decryptor=cipher.decryptor()

        #Decrypt and obtain plain text + possible padding
        plain_text=decryptor.update(cipher_text) + decryptor.finalize()

        #Check if unpadding is necessary
        if app.config['CRYPTOCONF'].get(algorithm).get('mode').get(mode).get('pad'):
            plain_text=unpaddingMsg(plain_text,blockSize)

        if not plain_text:
            return (False,"","Decryption: wrong pad due to wrong key!")

        return (True,plain_text,"OK")

    except crypto_exception.UnsupportedAlgorithm:
        return (False,"","Unsupported Algorithm")

def hash_msg(message:bytes,algorithm='SHA256'):
    #Get a hash "digest" for 'message'

    #Check if hash is compliant with the security requirements of
    #the Crypto-Engine: Just SHA-2 Family is supported.

    if not algorithm in app.config['HASHCONF']['hash']:
        return (False,"","Hash algortihm not supported")

    #Create a HashContext
    try:
        #digest=hashes.Hash(hashes.SHA256(),backend)
        #digest=getattr(hashes,'Hash')("{}()".format(algorithm),backend)
        digest = hashes.Hash(getattr(hashes,"{}".format(algorithm))(),backend)
        #digest=hashes.Hash(hashes.SHA256(),backend)
        digest.update(message)
        result=digest.finalize()

        #Encode Result
        result=base64.b64encode(result)
        return (True,result.decode(),"OK")
    except crypto_exception.UnsupportedAlgorithm:
        return (False,"","Hash algorithm not supported")


def gencert_content(entity,cert_type,private_key:bytes):

    #Load the private_key to the crypto engine.
    result,key=key_loader(private_key,'private')

    if not result:
        return (False,"","Key could not be loaded")


    #Check the Certification type from the request
    cert_type=cert_type.upper()
    if cert_type not in ['SELF','SIGNED','CSR'] :
        return (False,"","{} Invalid type of certificate".format(cert_type))

    #Create  the 'subject' of the certificate request
    result,subject,status=load_entity(entity)
    if not result:
        return (result,"",status)


    #Classify the certificate request type:

    if cert_type == 'CSR':
        csr=x509.CertificateSigningRequestBuilder()
        csr=csr.subject_name(subject)
        csr=csr.sign(key,hashes.SHA256(),backend)
        return (True,base64.b64encode(csr.public_bytes(serialization.Encoding.PEM)),"OK")

    elif cert_type == 'SIGNED':

        #Set the crypto Engine as the certificate issuer

        result,issuer,status=load_entity(app.config['CA_ISSUER_CONF'])
        #If this is the case, please check the Crypto-Engine CA configuration.
        #To find out the reason, debug the app and check the error via the above 'status' variable
        if not result:
            return (False,"","Crypto_Engine can not sign certificates at the moment")

        #Load the CA private key from 'CA_private_key_path)
        result,CA_private_key,status=load_CA_Key(app.config['CA_PRIVATE_KEY_PATH'])
        if not result:
            return (False,"","Crypto_Engine can not sign certificates at the moment")  #status)

        signing_key=CA_private_key

    else:
        signing_key=key
        issuer=subject


    #Building Certificate:
    cert=x509.CertificateBuilder()
    cert=cert.subject_name(subject)
    cert=cert.issuer_name(issuer)
    cert=cert.public_key(key.public_key())
    cert=cert.serial_number(x509.random_serial_number())
    cert=cert.not_valid_before(datetime.datetime.utcnow())
    cert=cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days= app.config['VALIDITY_PERIOD']))
    cert=cert.sign(signing_key,hashes.SHA256(),backend)


    if isinstance(cert,x509.Certificate):
        return (True,base64.b64encode(cert.public_bytes(serialization.Encoding.PEM)),"OK")
    else:
        return (False,"","Certificate could not be generated.")





