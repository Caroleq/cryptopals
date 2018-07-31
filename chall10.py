from base64 import b64decode
from binascii import hexlify, unhexlify
from chall2 import xor_bytes
from chall7 import AES_ECB_encrypt, AES_ECB_decrypt
from chall9 import pad_pkcs7



class AES_CBC:
	"""
		Class enabling AES encryption and decryption in CBC mode 
		Key and Initialization Vetor are fixed throughout lifetime of an object


	"""

	def __init__(self, key, iv=bytes([0]*16), block_size=16):

		"""
			Initializes class with key, IV, block_size 
		"""

		self.__key = key
		self.__iv = iv
		self.__block_size = block_size


	def decrypt(self, ciphertext):
		"""
			decrypts `ciphertext` with `self.__key` using `self.__iv` as initialization vector.
		"""

		blocks = [ ciphertext[i:i+self.__block_size] for i in range(0, len(ciphertext), self.__block_size ) ]

		plaintext = b''

		xor_next = self.__iv
		for block in blocks:

				plain_xored = AES_ECB_decrypt(block, self.__key)
				plaintext += xor_bytes(plain_xored, xor_next)
				xor_next = block

		return plaintext

	def encrypt(self, plaintext):
		"""
			encrypts `plaintext` with `self.__key` using `self.__iv` as initialization vector.
		"""

		blocks = [ plaintext[i:i+self.__block_size] for i in range(0, len(plaintext), self.__block_size ) ]

		ciphertext = b''
		xor_next = self.__iv
		for block in blocks:

				xored = xor_bytes(block, xor_next)
				cipher = AES_ECB_encrypt(xored, self.__key)
				ciphertext += cipher
				xor_next = cipher

		return ciphertext




if __name__ == "__main__":
	"""
		Decrypts https://cryptopals.com/static/challenge-data/10.txt
		then encrypts it again

	"""

	data = open('10.txt').read()
	raw = b64decode(data)
	key = b"YELLOW SUBMARINE" 
	aes_cbc = AES_CBC(key)

	decrypted = aes_cbc.decrypt(raw)

	print(decrypted.decode("utf-8") )
	assert raw == aes_cbc.encrypt(decrypted)


