from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64decode
from chall9 import pad_pkcs7


def AES_ECB_decrypt(encrypted, key):
	"""
		decrypts `encrypted` in AES ECB mode using `key`
	"""

	cipher = AES.new( key, AES.MODE_ECB)
	decrypted = cipher.decrypt( encrypted )

	return decrypted



def AES_ECB_encrypt( plaintext, key):
	"""
		encrypts `plaintext` with AES ECB mode using `key`
	"""

	cipher = AES.new( key, AES.MODE_ECB)
	encrypted = cipher.encrypt( plaintext )

	return encrypted


def pad_before_encrypt(plaintext, key):
	"""
		Padds  `plaintext` before encrypting
	"""
	plaintext = pad_pkcs7(plaintext)
	return AES_ECB_encrypt(plaintext, key)




if __name__ == "__main__":
	"""
		file decryption from https://cryptopals.com/static/challenge-data/7.txt
	"""
	data = open('7.txt').read()
	raw = b64decode(data)

	key = b'YELLOW SUBMARINE'

	print( AES_ECB_decrypt(raw, key).decode('utf-8') )


