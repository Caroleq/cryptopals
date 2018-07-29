from binascii import unhexlify, hexlify, b2a_hex

class FoundECBException(Exception):
	pass

def detect_AES_ECB( data_lines, block_size=16 ):
	"""
		detects indexes of line encrypted in ECB hint from the challenge: 'the same 16 byte plaintext block will always produce the same 16 byte ciphertext.''

		ECB_lines stores positions of detected strings
	"""

	ECB_lines = []

	for line_index, line in enumerate(data_lines):

		blocks = [ line[i:i+block_size] for i in range(0, len(line),block_size) ]

		try:
			for index1 in range(len(blocks)):
				for index2 in range(index1+1, len(blocks)):
					if blocks[index1] == blocks[index2]:
						ECB_lines.append(line_index)
						raise FoundECBException

		except FoundECBException as e:
			pass

	return ECB_lines





if __name__ == "__main__":
	"""
	  	Finds lines encrypted in AES ECB mode in https://cryptopals.com/static/challenge-data/8.txt
		Prints detected strings with line number
	"""

	data_lines = open('8.txt').readlines()

	raw_lines = [ str(unhexlify( line.strip('\n') ))  for line in data_lines ]

	indexes = detect_AES_ECB(raw_lines)

	for index in indexes:
		print("ECB mode detected in", index+1, "line, ciphertext :", data_lines[index].strip("\n") )
