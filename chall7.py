from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64decode


def AES_ECB_decrypt(encrypted, key):
	"""
		decrypts text encrypted in AES ECB mode using key
	"""

	cipher = AES.new( key, AES.MODE_ECB)
	decrypted = cipher.decrypt( encrypted )

	return decrypted




if __name__=="__main__":
	"""
		file decryption from https://cryptopals.com/static/challenge-data/7.txt
	"""
	data = open('7.txt').read()
	raw = b64decode(data)

	key = b'YELLOW SUBMARINE'

	print( AES_ECB_decrypt(raw, key).decode('utf-8') )






