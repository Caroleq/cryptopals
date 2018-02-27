from Crypto.Cipher import AES
from chall6 import xor_op
from chall9 import pad_pkcs7	
import binascii,base64, sys


def encrypt_cbc(text,key,IV='\x00'*16):
	"""ecrypts text with key - we assume it has proper lenght of 16 bytes"""
	text=pad_pkcs7(text)
	chunks=[text[i:i+16] for i in xrange(0,len(text),16)]
	cipher=AES.new(key, AES.MODE_ECB)
	encrypted=[]
	i=0
	while i<len(chunks):
		if i==0:
			xored=xor_op(IV,chunks[0])
			encrypted.append(cipher.encrypt(xored))
			i+=1
			continue
			
		prev=encrypted[i-1]
		xored=xor_op(encrypted[i-1],chunks[i])
		encrypted.append(cipher.encrypt(xored))
		i+=1

	return ''.join(encrypted)

def decrypt_cbc(text,key, IV='\x00'*16):
	"""decrytps text with key as shown o wikiepdia"""
	out=""
	blocks=[text[i:i+16] for i in xrange(0,len(text),16)]
	i=0
	cipher=AES.new(key,AES.MODE_ECB)
	while i<len(blocks):
		t=cipher.decrypt(blocks[i])
		if i==0:
			temp=xor_op(IV,t)
			out+=temp
			i+=1
			continue
		temp=xor_op(blocks[i-1],t)
		out+=temp
		i+=1
	return out

def main():
	data_f=open('10.txt')
	b64data=data_f.read()
	data=base64.b64decode(b64data)
	plain=decrypt_cbc(data,'YELLOW SUBMARINE')
	print plain

	back=encrypt_cbc(plain,'YELLOW SUBMARINE')
	b64=base64.b64encode(back)
	to_write=open('10_out','w')
	to_write.write(b64)
	data_f.close()
	to_write.close()
	

if __name__=="__main__":
	main()







