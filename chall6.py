from binascii import hexlify, unhexlify
from base64 import b64decode
from operator import itemgetter
from chall2 import xor_hex
from chall3 import break_xor_single_byte_by_freq



class RepeatedXOR:
	"""
		class for breaking ciphertext encrypted repeating XOR key
	"""


	def break_repeating_XOR_key( self, encrypted ):
		"""
			Full operation of breaking encryption of encrypted
		"""

		if encrypted == "" or type(encrypted) != str :
			raise Exception("Provide nonempty string")

		sizes = self.__get_key_sizes(encrypted)

		transposed = self.__transpose(encrypted, sizes[0][0])


		xor_key = ''
		for block in transposed:
			hex_block = hexlify( bytes(block,'ASCII') )
			xor_key += break_xor_single_byte_by_freq(hex_block)

		hex_encrypted = hexlify( bytes(encrypted,'ASCII') )
		hex_key = hexlify(  bytes(xor_key*int(len(encrypted)/sizes[0][0] +1), 'ASCII' ) )

		if len(hex_key) > len(hex_encrypted):
			hex_key = hex_key[:len(hex_encrypted)]

		hex_text = xor_hex(hex_encrypted, hex_key)

		return hex_text





	def __get_key_sizes(self, encrypted):
		"""
			Computes possible keysizes of xor key. I assume keysize is between 2 and 40
		"""

		if encrypted == "" or type(encrypted) != str :
			raise Exception("Provide nonempty string")


		sizes = []	# list of tupes ( lenght, score )
		for length in range(2,41):

			blocks = [ encrypted[i*length:(i+1)*length] for i in range( int(len(encrypted)/length) )]

			score = 0
			for block1, block2 in zip(blocks[:12], blocks[1:13]):
				score += self.hamming_distance(block1, block2)/length

			sizes.append((length, score))


		sizes.sort(key=itemgetter(1))
		return sizes


	def __transpose(self, encrypted, length):
		"""
			Multiple of i in range(0,length) will by in won block with the same multiples
			i. e. i, i+length, i+2*lenght,... character in string will be placed in one block
		"""

		if encrypted == "" or type(encrypted) != str :
			raise Exception("Provide nonempty string")

		transposed = [ '' for i in range(length ) ]

		for i in range(len(encrypted)):
			transposed[i%length] += encrypted[i]

		return transposed




	def hamming_distance( self, text1, text2 ):
		"""
			computes hamming distance between text1 and text2,
			where hamming distance is number of different bits between text1 and text2

		"""

		binary1	= ''.join( format(ord(x),'b').zfill(8) for x in text1)
		binary2	= ''.join( format(ord(x),'b').zfill(8) for x in text2)

		hamming_dist = 0
		
		for ind1, ind2 in zip(binary1, binary2):
			if ind1 != ind2:
				hamming_dist += 1

		return hamming_dist




if __name__ == "__main__":
	"""
	  breakes repeating xor from example
	"""

	test = RepeatedXOR();

	assert test.hamming_distance( 'wokka wokka!!!','this is a test') == 37 

	file_to_break = b64decode( open('6.txt').read() ).decode('utf-8')

	hexlified_plaintext = test.break_repeating_XOR_key(file_to_break )

	print( unhexlify( hexlified_plaintext).decode('utf-8') )


