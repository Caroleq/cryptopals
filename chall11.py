import random
import string
from chall9 import pad_pkcs7
from chall10 import encrypt_cbc
from Crypto.Cipher import AES

def encrypt_halfway(text,key):
	"""half of the text will be encrypted in CBC mode and half in ECB mode"""

	choice=random.randint(0,1)
	iv=''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)])
	text=pad_pkcs7(text)
	data=[text[i:i+16] for i in xrange(0,len(text),16)]
	div=len(data)/2
	p1=''.join(data[:div])
	p2=''.join(data[div:])
	cipher=AES.new(key,AES.MODE_ECB)
	if choice==0:
		out=cipher.encrypt(p1)
		out+=encrypt_cbc(p2,key,iv)
		return out
	out=encrypt_cbc(p1,key,iv)
	out+=cipher.encrypt(p2)
	return out
	

def detect(text):
	"""checks which half of text has been encrytped in ecb and which in cbc mode"""
	data=[text[i:i+16] for i in xrange(0,len(text),16)]
	p1=data[:len(data)/2]
	i=0
	while i< len(p1):
		j=i+1
		while j<len(p1):
			if p1[i]==p1[j]:
				return 'ecb'
			j+=1
		i+=1
	return 'cbc'	
		

def add_rand(text):
	"""appends random strings of random lenght at the beginning and at the end of string"""
	ap=random.randint(5,10)
	su=random.randint(5,10)
	
	appendix=''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(ap)])
	suffix=''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(su)])
	return appendix+text+suffix

def main():
	data='0'*100
	key=''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)])
	beautified=add_rand(data)
	encr=encrypt_halfway(beautified,key)
	if detect(encr)=='ecb':
		print 'ecb mode detected'
	else:
		print 'cbc mode detected'

if __name__=="__main__":
	main()


