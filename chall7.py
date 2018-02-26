from Crypto.Cipher import AES
from Crypto import Random
import base64

def main():
	key=b'YELLOW SUBMARINE'
	cipher=AES.new(key,AES.MODE_ECB)
	
	data_f=open('7.txt')
	b64data=data_f.read()
	data=base64.b64decode(b64data)
	encrypted=cipher.decrypt(data)
	print encrypted


if __name__=="__main__":
	main()






