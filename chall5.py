from  binascii import hexlify
from chall2 import xor_hex


def encrypt_xor( plaintext, key):
	"""
		XORS plaintext with repeted key using function from challenge 2.
		Splits plaintext on every '\n' char
	"""

	lines = plaintext.split('\n')


	xor = ""
	for line in lines:

		to_multiply = int(len(line)/len(key))+1

		hexlified1 = str( hexlify( bytes( line, 'utf-8' ) ) )[2:-1]
		hexlified2 = str( hexlify( bytes(key*to_multiply, 'utf-8')) )[2:len(hexlified1)+2]	
	
		xor += xor_hex(hexlified1, hexlified2) + '\n'
	

	return xor



if __name__=="__main__":
	
	secret = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key = "ICE"

	print ( encrypt_xor(secret, key), end='' )


