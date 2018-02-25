from __future__ import division
import base64
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

def break_sigle_xor(to_break):
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



def hamm_dist(str1,str2):
	"""function to compute hamming distance of two strings"""
	if len(str1)!=len(str2):
		raise Exception
	str1_b=''.join(format(ord(x),'b').zfill(8) for x in str1)
	str2_b=''.join(format(ord(x),'b').zfill(8) for x in str2)
	dist=0
	i=0
	while i < len(str1_b) and i<len(str2_b):
		if str1_b[i]!=str2_b[i]:
			dist+=1
		i+=1
	return dist

def get_xor_len(data):
	"""gets the probable xor length from hamming distance"""
	dists=[]
	for i in range(2,41):
		av_dist=0
		for j in range(0,12):
			s1=data[j*i:j*i+i]
			s2=data[j*i+i:j*i+2*i]
			av_dist+=(hamm_dist(s1,s2))/i
		dists.append([i,av_dist])
	dists.sort(key=itemgetter(1))
	return dists[:3]

def transpose(t_blocks):
	"""creates new blocks by first numbers of t_blocks"""
	blocks=[]
	length=len(t_blocks[0]) 
	for i in range(length):
		blocks.append("")
	for block in t_blocks:
		i=0
		if len(block)<length:
			continue
		while i<length:
			blocks[i]+=block[i]
			i+=1
	return blocks

def xor_op(text,key):
	i=0
	out=""
	while i<len(text):
		out+=chr(ord(text[i])^ord(key[i%len(key)]))
		i+=1
	return out

def main():
	data_f=open('6.txt')
	data=data_f.read()
	decr=base64.b64decode(data)
	data_f.close()
	items= get_xor_len(decr)
	k_size=[items[i][0] for i in xrange(0, len(items),1)]
	k_size=k_size[:1]
	for key in k_size:
		blocks=[decr[i:i+key] for i in xrange(0,len(decr),key)]
		t_blocks=transpose(blocks)
		passwd=""
		for block in t_blocks:
			passwd+=break_sigle_xor(block)
			
		text=xor_op(decr,passwd)
		print text

		
if __name__=="__main__":
	main()



