from  binascii import hexlify, unhexlify
from operator import itemgetter
from chall3 import  break_xor_single_byte_by_freq, frequency_table
from chall2 import xor_hex



def find_line(data_lines):
	"""
    Tries to break each line with single xor key. Then sorts list of 2-elem list [line, score] according to best score in frequency tables
	"""
	local_scores=[]
	for line in data_lines:

		c = break_xor_single_byte_by_freq(line)
		c = ord(c)

		score = 0

		unhexlified = unhexlify(line)
		for letter in unhexlified:
			l = chr(letter^c)

			if l in frequency_table.keys():
				score += frequency_table[l]

		local_scores.append([line,score])


	local_scores.sort(key=itemgetter(1), reverse=True)
	return local_scores


if __name__ == "__main__":
	"""
      Solves problem from https://cryptopals.com/static/challenge-data/4.txt
	"""


	data_file = open('4.txt')
	hex_data = data_file.readlines()
	raw_data = []

	for line in hex_data:
		raw_data.append(line.rstrip('\n'))

	sorted_lines = find_line(raw_data)

	best = sorted_lines[0][0]

	char =  break_xor_single_byte_by_freq( best ) 	
	payload = hexlify( bytes(char*len( best ),'ASCII') )[2:len( best )+2]

	print( unhexlify(xor_hex( best ,payload)) )

	data_file.close()











