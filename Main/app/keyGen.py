from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa,ec
from cryptography.hazmat.primitives import serialization
from .views import app

'''Default values'''
public_exponent=65537
backend=default_backend() #Around OpenSSL
#Serialization
#Encoding=serialization.Encoding.PEM
PrivateFormat=serialization.PrivateFormat.TraditionalOpenSSL
EncryptAlgorithm=serialization.NoEncryption()


def asymmetric_check(algorithm,keysize:int):
    #Check if the protocol is allowed:
    if not algorithm in app.config['CONF_ASYMMETRIC'].get('protocol'):
        return (False,"Algorithm: {} not supported".format(algorithm))
    if not keysize in app.config['CONF_ASYMMETRIC'].get('keysize'):
        return (False,"{} bits for key size is not supported".format(keysize))
    return (True,"OK")

def public_key_format(encoding):
    if encoding =="SSH":
        PublicFormat = serialization.PublicFormat.OpenSSH
        encoding='OpenSSH'
    else:
        PublicFormat = serialization.PublicFormat.SubjectPublicKeyInfo

    return (encoding,PublicFormat)

'''Generate a key-pair. Eprivate and Epublic are meant for enconding type'''
def keyGenPair(algorithm,size:int,Eprivate='PEM',Epublic='SSH'):

    algorithm=algorithm.upper()
    Eprivate=Eprivate.upper()
    Epublic = Epublic.upper()


    if not all(elem in app.config['CONF_ASYMMETRIC']['encoding'] for elem in [Eprivate,Epublic]) or Eprivate == 'SSH':
        return (False,"","","Key-pair format not supported!")

    #Handler for Public Keys
    Epublic,PublicFormat=public_key_format(Epublic)


    '''Check if the parameters input are compliant
      with the security of the crypto engine'''
    result,status=asymmetric_check(algorithm,size)

    if not result:
        return (result, "","",status)

    ''' RSA Key-pair Generation'''
    if algorithm=='RSA':

        #Generation of a private key object
        keyPrivate =rsa.generate_private_key(public_exponent,size,backend)

        '''Getting the private key object.
           Default values for serialization of the private key:
           Encoding Type: PEM. (DER--->Can be extended)
           Format: Traditional OpenSSL (PKCS8 can be extended)
        '''

        private_key = keyPrivate.private_bytes(getattr(serialization,"Encoding")(Eprivate), PrivateFormat,
                                         EncryptAlgorithm)

        #Public Key object
        keyPublic=keyPrivate.public_key()
        '''Generation of public key'''
        public_key=keyPublic.public_bytes(getattr(serialization,"Encoding")(Epublic),PublicFormat)

    #ECDSA Key-pair generation
    elif algorithm == 'ECDSA':

        #Generation of private key object
        #P-384bit curve (Defined in NSA Suite B)
        keyPrivate=ec.generate_private_key(ec.SECP384R1,backend)

        #Generation of private key:
        private_key=keyPrivate.private_bytes(getattr(serialization,"Encoding")(Eprivate),PrivateFormat,
                                             EncryptAlgorithm)
        #Public Key object
        keyPublic=keyPrivate.public_key()

        #Generation of public key
        public_key=keyPublic.public_bytes(getattr(serialization,"Encoding")(Epublic),PublicFormat)

    return (result,private_key,public_key,status)




