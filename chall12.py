from Crypto.Cipher import AES
from chall9 import pad_pkcs7
from chall11 import detect
import string, random
import base64

#################################################################################################################################
##################################			server side				#################################
#################################################################################################################################


def server(user_input):
	"""returns encrypted with secret text user input """
	data=base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"+
	                       "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"+
        	               "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"+
                	       "YnkK")
	if not hasattr(server,"key"):
		server.key=''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)])

	cipher=AES.new(server.key,AES.MODE_ECB)
	return cipher.encrypt(pad_pkcs7(user_input+data))


##################################################################################################################################
########################				client side				##################################
##################################################################################################################################

def byte_at_a_time(cracked,block_size):
	"""cracks the next byte of encrypted using known already cracked part and information of blocksize"""
	p_size=(block_size-(1+len(cracked)))%block_size
	prefix='A'*p_size
	to_cmp=p_size+len(cracked)+1				#to_cmp is a multiple of block_size
	
	original=server(prefix)[:to_cmp]			# to_cmp/block_size number of blocks will be compared
	for i in range(255):
		crafted=prefix+cracked+chr(i)
		if server(crafted)[:to_cmp]==original:		#we try to match user input
			return chr(i)
	return ""

def check_mode():
	"""checks if text is encrypted in ecb mode"""
	probe='A'*48
	encrypted=server(probe)
	if detect(encrypted)!='ecb':
		return False
	return True
	

def crack_message(block_size):
	"""crack whole message getting bytes one by one"""
	
	out=""
	while True:
		c=byte_at_a_time(out,block_size)		#in each iteration new char is discovered
		if c=="":
			break
		out+=c
	return out

def get_bsize():
	"""feeds server with payloads: 'A'*n to discover block size of cipher"""
	i=2
	while i<102:
		payload='A'*i
		encrypted=server(payload)
		if encrypted[:i/2]==encrypted[i/2:i]:
			return i/2
		i+=2


def main():
	"""first of all i checked if encryption is ecb instead of guessing the block_size"""
	block_size=get_bsize()
	if not check_mode():
		print 'not ecb mode!\nTerminating....'
		exit()
	print crack_message(block_size)



if __name__=="__main__":
	main()




