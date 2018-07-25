from __future__ import division
import binascii
from chall2 import xor_hex

frequency_table = {	'E':1, 'e':1,
		  		   	'T':12/13, 't':12/13,
		   		   	'A':11/13, 'a':11/13,
		   			'O':10/13, 'o':10/13,
		   			'I':9/13, 'i':9/13, 
		   			'N':8/13, 'n':8/13,
		  			' ':7/13, 
		   			'S':6/13, 's':6/13,
		   			'H':5/13, 'h':5/13,
		   			'R':4/13, 'r':4/13,
		   			'D':3/13, 'd':3/13,
		   			'L':2/13, 'l':2/13,
		   			'U':1/13, 'u':1/13
            	  }

def break_xor_single_byte_by_freq( to_break ):
	"""
	  Function tries to decrypt text (in hex format) xored with single string by using frequency table of characters (for English language)
	  We choose ASCII code, where given text gets the highest score according to frequency table
	"""	

	to_break = binascii.unhexlify(to_break)

	max_score_letter = '\x00'
	max_score = 0

	for char in range(256):
		score=0.0

		for letter in to_break:

			c = chr(letter^char)
			if c in frequency_table.keys():
				score += frequency_table[c]

		if score > max_score:
			max_score_letter = chr(char)
			max_score = score


	return max_score_letter


if __name__ == "__main__":
    encoded='1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

    char = break_xor_single_byte_by_freq(encoded)

    payload = binascii.hexlify( bytes(char*len(encoded),'ASCII') )[2:len(encoded)+2]

    print( binascii.unhexlify(xor_hex(encoded ,payload)) )



