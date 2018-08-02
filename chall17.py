from random import randint
from base64 import b64decode
from chall9 import pad_pkcs7
from chall10 import AES_CBC
from chall15 import pkcs_check, PaddingException, pkcs_unpad


"""
	Deciphering may fail for the last block

"""




class Server():
	"""
		Simulates vulnerable application
		
	"""

	def __init__(self):
		"""
			sets random key 
		"""

		self.__key = self._generate_random_key()
		self.__aes_cbc = AES_CBC( self.__key )


	def _generate_random_key(self):
		"""
		  Generates random key for for encryption 
			of provided plaintexts
		"""
		key = [ randint(0,255) for i in range(16) ]
		return bytes(key)


	def encrypt(self, plaintext, iv=bytes([0]*16)):
		"""
			Encrypts text with CBC mode
		"""

		cipher = AES_CBC( self.__key, iv )
		self.__secret = cipher.encrypt( plaintext )
		return self.__secret


	def decrypt(self, ciphertext, iv=bytes([0]*16) ):
		"""
			Decrypts ciphertext. 
			Returns true if ciphertext was decrypted or raises an exception
		"""

		cipher = AES_CBC( self.__key, iv )
		plaintext = cipher.decrypt(ciphertext)

		pkcs_check(plaintext)
		return plaintext


	def get_secret(self):
		return self.__secret






class OraclePadding():
	"""
		Class for running Oracle Padding attack
		Decrypts text encrypted with AES CBC
		Following conditions are required:
		 - class must be able to provide its own ciphertext
		 - info if decryption error connected with bad padding has occured
	"""


	def __init__(self, server_target):
		"""
			Initializes target to send modiefied ciphertext
		"""
		self.__server_target = server_target



	def run_attack(self, ciphertext):
		"""
			Runs Oracle Padding attack.
		"""

		plaintext = b''
		blocks = [ ciphertext[i:i+16] for i in range(0, len(ciphertext), 16 ) ]

		BLOCK_LENGTH = 16


		# i append iv as the first block
		blocks.insert(0, bytes([0]*16))					

		# in each loop i decrypt `block` using `prev`
		for prev, block in zip( blocks, blocks[1:]):

			# i initialize vars to store decrypted block and and payload 
			decrypted = b''
			padding = [0]*BLOCK_LENGTH


			# i decrypt char by char of the block starting with the last byte in block
			for index in range(BLOCK_LENGTH-1, -1, -1):

				# size of the padding we want to simulate
				padding_size = BLOCK_LENGTH - index
				
				# i try to get proper unpadding for any ascii value
				for i in range(256):

					# i create iv vector by getting first `index` bytes of `prev` (in normal case `prev` would be this vector)
					# i append ascii value
					# and finally append `padding_size - 1` bytes so that after decryption we obtain bytes with the value: `paddings_size` 
					# on the last `padding_size - 1` positions
					# our goal is to find ascii where on `index` position we get `padding_size` value and hence 
					# get valid padding
					payload = prev[:index] + bytes([i]) + bytes([ padding_size^j  for j in padding[index + 1: ] ])

					try:

						self.__server_target( block, payload)

					except PaddingException:
						continue

					# if we got valid padding, it means that the new plaintext at `index` is `padding_size`
					# knowing `payload[index]`, we get that text going out of decrypted
					# block (before XORing ) is `i ^ padding_size`
					# hence plaintext at this position is `i ^ padding_size ^ prev[index]`
					# while creating next payloads we want to get increased value of decrypted values at that position
					# thus i xor these values in the loop [ padding_size^j  for j in padding[index + 1: ] ]
					padding[index] = padding_size ^ i
					decrypted  = bytes([padding[index] ^ prev[index]]) + decrypted
					break

			plaintext += decrypted

		return pkcs_unpad( plaintext )





def setup_server():
	"""
		Creates server instance and encrypts one of the strings with CBC mode
		Returns server instance
	"""


	server = Server()

	data = open('17.txt').readlines()
	index = randint(0,9)

	server.encrypt( bytes(pad_pkcs7(b64decode(data[index]))) )

	return server


if __name__ == "__main__":
	"""
		Opens file with ciphers from challenge page.
		Encrypts all of with random key, then decrypts 
		them using Oracle Padding attack
	"""

	server = setup_server()
	secret = server.get_secret()

	oracle_padding = OraclePadding( server.decrypt )
	decrypted = oracle_padding.run_attack(secret)
	print( decrypted )