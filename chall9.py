

def pad_pkcs7(text, num=16):
	"""
		Data are padded  so after function execution len(text)%num == 0
		If  in original text len(text)%num == 0, additial padding block is added

		Padding value is chr(num - len(text)%num)
	"""

	padding_length = num - len(text)%num
	padding_value = chr(padding_length)

	text += padding_value*padding_length

	return text



if __name__=="__main__":
	"""
		Example from challenge
	"""

	assert pad_pkcs7("YELLOW SUBMARINE", 20) == "YELLOW SUBMARINE\x04\x04\x04\x04"

