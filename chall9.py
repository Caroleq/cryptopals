import binascii

def pad_pkcs7(text, num=16):
	"""padding to multiply of num"""
	to_pad=num-len(text)%num
	text+=chr(to_pad)*to_pad
	return text

def main():
	text="YELLOW SUBMARINE"
	padded=pad_pkcs7(text)
	print padded

if __name__=="__main__":
	main()

