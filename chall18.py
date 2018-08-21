from Crypto.Cipher import AES
import struct
from random import randint
from base64 import b64decode
from chall2 import xor_bytes
from chall9 import pad_pkcs7

class AES_CTR:
	"""
		class for encrypting data in CTR mode

	"""

	def __init__(self, key, nonce=0):
		self.__cipher = AES.new( key, AES.MODE_ECB )
		self.__nonce = nonce

	def encrypt( self, data ):
		"""
			encrpyts data in CTR mode
		"""
		ciphertext = b''
		blocks = [ data[i:i+16] for i in range(0, len(data), 16 ) ]
		nonce = self.__nonce

		# for each block nonce is encrypted
		# then plaintext is ored with that value
		# nonce is increased by one
		for block in blocks:
			ciphertext += xor_bytes( block, self.__cipher.encrypt( struct.pack('<QQ', self.__nonce, nonce))[:len(block)]  )
			nonce += 1

		return ciphertext

	def decrypt( self, data ):
		"""
			decrypts data encrypted in CTR mode
		"""
		# data is decrypted just like they are encrypted
		# so i can ust call encrypt() method for that datas
		return self.encrypt(data)


if __name__ == "__main__":
	"""
		i decrypt example from the challenge
	"""

	secret = b64decode( 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==' )
	key = b'YELLOW SUBMARINE'
	nonce = 0

	ctr = AES_CTR(key, nonce)

	print( ctr.decrypt(secret))

