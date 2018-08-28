'''CRYPTO-ENGINE: Configuration Parameters'''

'''Key Generation: Public-private Key pair. Algorithms supported:
RSA and ECDSA with keysize 2048 and 4096. Different encoding formats are supported
for private-key, the crypto engine also supports SSH format.'''

CONF_ASYMMETRIC={'protocol':['RSA','ECDSA'], 'keysize':[2048,4096],'encoding':['PEM','DER','SSH']}


'''Configuration Parameters for Symmetric cryptography, used in encryption and 
decryption.'''

MODES={'CBC':{'pad':True},'CTR':{'pad':False},
          'OFB':{'pad':False},'CFB':{'pad':False}}

#The value for the key 'name' corresponds to the name how cryptography recognizes the corresponding algorithm.
CRYPTOCONF={'3DES':{'name':'TripleDES','blocksize':8,'keysize':[192],'mode':MODES},
            'AES' :{'name': 'AES','blocksize':16,'keysize':[192,256],'mode':MODES}}

'''Configuration parameters for Asymmetric cryptography, used in both
encryption and decryption. Currently only RSA is supported for these operations'''

ASYMCONF={'RSA':{'keysize':[2048,4096]}}

'''Configuration parameters for hashing. This Crypto-Engine version only supports
 hashing algorithms from the SHA-2 family (For security reasons'''

HASHCONF={'hash':['SHA224','SHA256','SHA384','SHA512']}

'''Configuration parameters for Certificate Generation '''

CA_PRIVATE_KEY_PATH="app/CA_key.pem"       #Location of private key (Crypto-Engine acts as a CA)
VALIDITY_PERIOD=10                         # in days

#Crypto-Engine: Certificate Authority issuer details
CA_ISSUER_CONF={'country': "SW",'state':"Skane",
                'locality':"LUND",'organization':"RISE",
                'common':"COLA.com"}



