import os

# getRandom

'''This function returns a int random number derived from the
byte object generated from the os.urandom function '''

def getRandom(size: int, byteorder: str='big',formatR='integer') -> int:
    b=os.urandom(size)

    if formatR=="binary":
        return b

    if byteorder == 'big':
        return sum(j * 256 ** i for i, j in enumerate(b[::-1]))
    elif byteorder == 'little':
        return sum(j * 256 ** i for i, j in enumerate(b))
    else:
        raise ValueError("Crypto-Engine: Error byteorder must be either 'little' or 'big'.")

