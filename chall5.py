import binascii


def encrypt_xor(text,key):
	i=0
	out=""
	for letter in text:
		out+=chr(ord(key[i])^ord(letter))
		i+=1
		if i==len(key):
			i=0
	return out

def main():
	to_encrypt="Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key="ICE"
	print binascii.hexlify(encrypt_xor(to_encrypt,key))


if __name__=="__main__":
	main()


