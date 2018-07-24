
def pkcs_check( plaintext ):
	"""
		Returns true when plaintext is padded correctly
		Otherwise it throws an Exception

		For not-existing objects functions returns True
	"""

	if plaintext == None:
		return False

	pad_ascii = ord(plaintext[-1])

	if pad_ascii not in range(1,17):
		raise Exception("Invalid Padding")

	if len(plaintext) < pad_ascii :
		raise Exception("Invalid Padding")

	if plaintext[-pad_ascii:] != chr(pad_ascii)*pad_ascii:
		raise Exception("Invalid Padding")

	return True


if __name__ == "__main__":

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