from base64 import b64decode
from random import randint
import string
from chall2 import xor_bytes
from chall3 import frequency_table
from chall18 import AES_CTR


frequency_digrams = {
					 'th': 1.0,
	 				 'er': 0.9666666666666667,
					 'on': 0.9333333333333333,
					 'an': 0.9,
					 're': 0.8666666666666667,
					 'he': 0.8333333333333334,
					 'in': 0.8,
					 'ed': 0.7666666666666667,
					 'nd': 0.7333333333333333,
					 'ha': 0.7,
					 'at': 0.6666666666666666,
					 'en': 0.6333333333333333,
					 'es': 0.6,
					 'of': 0.5666666666666667,
					 'or': 0.5333333333333333,
					 'nt': 0.5,
					 'ea': 0.4666666666666667,
					 'ti': 0.43333333333333335,
					 'to': 0.4,
					 'it': 0.36666666666666664,
					 'st': 0.3333333333333333,
					 'io': 0.3,
					 'le': 0.26666666666666666,
					 'is': 0.23333333333333334,
					 'ou': 0.2,
					 'ar': 0.16666666666666666,
					 'as': 0.13333333333333333,
					 'de': 0.1,
					 'rt': 0.06666666666666667,
					 've': 0.03333333333333333
				 }


def check_digram( first, second ):
	"""
		verifies if `first` + `second` belong to most common two-letter phrases
		gives negative points for uncommon letter concatenation
	"""

	if type( first ) != str:
		first = chr( first )

	if type( second ) != str:
		second = chr( second )

	if first not in string.ascii_letters or second not in string.ascii_letters:
		return 0

	if not ( first == ' ' or first == '\'')  and second.isupper():
		return -0.5 

	digram = first.lower() + second.lower() 
	if digram in frequency_digrams:
		return frequency_digrams[digram]
	return 0


def break_first( ciphertexts ):
	"""
		aims to find first byte of
		keystream, uses frequency_table

		extra points for big letter
	"""

	scores = (-1, -1) # ( highest_score, chr_with_highest_score)

	for ascii in range(256):
		score = 0
		for ciphertext in ciphertexts:
			letter = chr( ciphertext[ 0 ] ^ ascii ) 
			if letter in frequency_table:
				score += frequency_table[ letter ]
			if letter in string.ascii_uppercase:
				score += 0.5

		if score > scores[0]:
			scores = (score, ascii)
	return bytes( [ scores[1] ] )



def break_next_byte(keystream, ciphertexts, position):
	""" 
		finds most probable next byte of keystream

		len(keystream) > 0 

		uses frequency_table from challenge 2
		and frequency_digrams  - set of most common two letter phrases 
		in english

	"""

	scores = (-1, -1) # ( highest_score, chr_with_highest_score)	
	for ascii in range(256):
		score = 0
		for ciphertext in ciphertexts:
			if position > len(ciphertext) -1:
				continue
			letter = chr( ciphertext[ position ] ^ ascii ) 
			if letter in frequency_table:
				score += frequency_table[ letter ]
			if letter not in string.printable or letter == '\r':
				score -= 1

			score += check_digram( ciphertext[position], keystream[-1] ^ ciphertext[position-1] )

		if score > scores[0]:
			scores = (score, ascii)

	return bytes( [ scores[1] ] )



def break_CTR_by_frequency( data ):
	""" 
		i try to get keystream from `data` ( list of strings )
		Each string has been encrypted with the same nonce and key
		which means keystream for every cipher is the same
	"""
	
	keystream = b''
	keystream += break_first( data )

	length = max( [ len(line) for line in data] )

	for i in range( 1, length ):
		keystream += break_next_byte( keystream, ciphertexts, i )

	return keystream

def generate_key():
	""" generates 16 random bytes"""
	key = [ randint(0,255) for i in range(16) ]
	return bytes( key )


def encrypt_data():
	""" encrypts data from with random key and fixed nonce"""
	key = generate_key()
	ctr = AES_CTR(key, 0)

	data_lines = open('19.txt').readlines()

	ciphertexts = []

	for  line in data_lines:
		ciphertexts.append( ctr.encrypt( b64decode( line ) ) )

	return ciphertexts


if __name__ == "__main__":
	"""
		i get plaintext of lines provided in 
		challenge and encrypted in CTR mode with 
		repeated nonce

		in longer strings there are some bugs in the end since 
		there is less strings for comparing (shorter are already encrypted)
	"""

	ciphertexts = encrypt_data()
	keystream = break_CTR_by_frequency( ciphertexts )

	for ciphertext in ciphertexts:
		x = xor_bytes( ciphertext, keystream[:len(ciphertext)] )
		print( x )