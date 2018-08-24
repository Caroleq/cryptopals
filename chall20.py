from random import randint
from base64 import b64decode
from binascii import hexlify, unhexlify
from chall2 import xor_bytes
from chall3 import break_xor_single_byte_by_freq
from chall18 import AES_CTR


class break_CTR:
	"""
		class for finding keystream for many strings
		encrypted with the same keystream

		i used some code from challenge 6 
	"""

	def break_cipher( self, ciphertexts ):
		"""
			returns keystream used for encrypting ciphertexts
		"""

		truncated = self.__truncate(ciphertexts)
		ciphertexstring = b''.join( truncated )

		keystream_size = len( truncated[0] )

		transposed = self.__transpose( ciphertexstring, keystream_size )

		xor_key = b''
		for block in transposed:
			hex_block = hexlify( block )
			xor_key += bytes( [ ord( break_xor_single_byte_by_freq(hex_block) ) ] )

		return xor_key


	def __truncate(self, ciphertexts ):
		"""
			truncates ciphertexts to 
			the length of the shortest one 
		"""

		length = min( [ len(ciphertext) for ciphertext in ciphertexts] )
		return [ ciphertext[:length] for ciphertext in ciphertexts ]

	def __transpose(self, encrypted, length):
		"""
			Multiple of i in range(0,length) will by in won block with the same multiples
			i. e. i, i+length, i+2*lenght,... character in string will be placed in one block
		"""

		if encrypted == "" or type(encrypted) != bytes :
			raise Exception("Provide nonempty bytestring")

		transposed = [ b'' for i in range(length ) ]

		for i in range(len(encrypted)):
			transposed[i%length] += bytes( [encrypted[i] ])

		return transposed



def generate_key():
	""" generates 16 random bytes"""
	key = [ randint(0,255) for i in range(16) ]
	return bytes( key )


def encrypt_data():
	""" encrypts data from with random key and fixed nonce"""
	key = generate_key()
	ctr = AES_CTR(key, 0)

	data_lines = open('20.txt').readlines()

	ciphertexts = []

	for  line in data_lines:
		ciphertexts.append( ctr.encrypt( b64decode( line ) ) )

	return ciphertexts




if __name__ == "__main__":
	"""
			i decrypt sentences from challenge file
	"""

	ciphertexts = encrypt_data()
	break_ctr = break_CTR()
	keystream = break_ctr.break_cipher( ciphertexts )
	l = len(keystream)

	for ciphertext in ciphertexts:
		x = xor_bytes(keystream, ciphertext[:l] )
		print( x )

