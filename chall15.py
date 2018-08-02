

class PaddingException(Exception):
	pass


def pkcs_check( plaintext ):
	"""
		Returns true when plaintext is padded correctly
		Otherwise it throws an Exception

		For not-existing objects functions returns False
	"""


	if type(plaintext) != str and type(plaintext) != bytes:
		raise PaddingException("Invalid Type")

	if plaintext == None:
		return False

	if type(plaintext) == str:
		pad_ascii = ord(plaintext[-1])
	else:
		pad_ascii = plaintext[-1]

	if pad_ascii not in range(1,17):
		#print(pad_ascii)
		raise PaddingException("Invalid Padding Range")

	if len(plaintext) < pad_ascii :
		raise PaddingException("Invalid Padding Length")


	if type(plaintext) == str:
		if plaintext[-pad_ascii:] != chr(pad_ascii)*pad_ascii:
			raise PaddingException("Invalid Padding")
	else:
		if plaintext[-pad_ascii:] != bytes( [pad_ascii]*pad_ascii) :
			raise PaddingException("Invalid Padding")

	return True

def pkcs_unpad(plaintext):
	"""
		Removes trailing padding
	"""

	pkcs_check( plaintext )

	if type(plaintext) == str:
		return plaintext[:-ord(plaintext[-1])]
	else:
		return plaintext[:-plaintext[-1]]



if __name__ == "__main__":
	"""
		Simple tests from cryptopals challenge
	"""

	valid = "ICE ICE BABY\x04\x04\x04\x04"
	invalid1 = "ICE ICE BABY\x05\x05\x05\x05"
	invalid2 = "ICE ICE BABY\x01\x02\x03\x04"

	assert pkcs_check(valid) == True

	try:
		pkcs_check(invalid1)
	except Exception as e:
		if str(e) != "Invalid Padding":
			raise Exception("Test failed for invalid1")
	else:
		raise Exception("Test failed for invalid1")


	try:
		pkcs_check(invalid2)
	except Exception as e:
		if str(e) != "Invalid Padding":
			raise Exception("Test failed for invalid2")
	else:
		raise Exception("Test failed for invalid2")