from __future__ import division
import binascii
from operator import itemgetter

frequency_table={'E':1, 'e':1,
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
		 'U':1/13, 'u':1/13}

def break_xor_single_byte_by_freq(to_break):
	"""test for single xor"""	
	max_score_letter='\x00'
	max_score=0
	for char in range(0,256):
		score=0.0
		for letter in to_break:
			c=chr(ord(letter)^char)
			if c in frequency_table.keys():
				score+=frequency_table[c]
		if score > max_score:
			max_score_letter=chr(char)
			max_score=score
	return max_score_letter

def find_line(data_table):
	local_scores=[]
	for line in data_table:
		out=""
		c=break_xor_single_byte_by_freq(line)
		c=ord(c)
		score=0
		for letter in line:
			l=chr(ord(letter)^c)
			out+=l
			if l in frequency_table.keys():
				score+=frequency_table[l]

		local_scores.append([out,score])
	local_scores.sort(key=itemgetter(1),reverse=True)
	return local_scores


data_file=open('4.txt')
hex_data=data_file.readlines()
raw_data=[]

for line in hex_data:
	raw_data.append(binascii.unhexlify(line.rstrip('\n')))

sc=find_line(raw_data)
print sc[0][0]

data_file.close()





