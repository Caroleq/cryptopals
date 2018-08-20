from random import randint
from Crypto.Cipher import AES
from chall9 import pad_pkcs7
from chall10 import AES_CBC

class CryptoGenerator:
	"""
		class for generating ciphers of user provided
		data and verifying if user is admin
	"""

	def __init__(self):
		"""
			creates cipher used for encryption and decryption
		"""

		key = self.__get_key()
		iv = bytes([0]*16)
		self.__cipher = AES.new(key,  AES.MODE_CBC, iv)
		self.__cipher = AES_CBC(key, iv)


	def __get_key(self):
		"""
			used for key generation
		"""
		key = [ randint(0,255) for i in range(16) ]
		return bytes(key)

	def __delete_delimeters(self, data ):
		"""
			removes ';' and '=' from `data`
		"""

		sanitized = bytes( [ byte_ for byte_ in data if (byte_ != ord(';') and byte_ != ord(':')) ] )
		return sanitized





	def encrypt_data(self, data):
		"""
			encrypts user data and returns ciphertext
		"""

		data = self.__delete_delimeters(data)

		to_encrypt = b"comment1=cooking%20MCs;userdata=" + data + b";comment2=%20like%20a%20pound%20of%20bacon"

		return self.__cipher.encrypt( pad_pkcs7( to_encrypt) )

	def is_admin(self, ciphertext):
		"""
			decrypts provided ciphertext and 
			looks for  ";admin=true;" substring
		"""

		plaintext = self.__cipher.decrypt( ciphertext )
		print ( plaintext )
		if  b";admin=true;" in plaintext:
			return True
		return False



def get_modified_cipher( cipher_block, real_plaintext, modified_plaintext):
	"""
		returns cipherblock that will be decrypted to modified_plaintext
	"""
	modified_cipher = bytes( [ cipher_block[i] ^ real_plaintext[i] ^ modified_plaintext[i]  for i in range(len(real_plaintext)) ]  )

	return modified_cipher

def bit_flipping():
	"""
		runs bit-flipping attack
		to evaluate encrypted user
		as admin 
	"""

	cg = CryptoGenerator()

	# i know how the plaintext will approximately look like since 
	# i can provide data of arbitrary length
	# i know encryption looks like
	#  cipher( [appendix] | [user_data] | [suffix])

	payload =  bytes( [ord('A')]*1000 )

	ciphertext = cg.encrypt_data(payload)

	# in i'th block decryption looks like:
	# Pi = C(i-1) XOR D( Ci )
	# since i know plaintext and C(i-1)
	# i can get D( Ci ) = Pi XOR C(i-1)
	# i want to obtain Pi contains ";admin=true;"
	# and i have ";admin=true;" XOR D( Ci ) = modified_Ci
	# now i can modify C(i-1) so after decryption 
	# i obtain desired plaintext
	
	prev_cipher = ciphertext[80:96]

	modified_cipher = get_modified_cipher(prev_cipher, b'AAAAAAAAAAAAAAAA', b';admin=true;AAAA' )

	malicious_ciphertext = ciphertext[:80] + modified_cipher + ciphertext[96:]

	if cg.is_admin( malicious_ciphertext ):
		print( "Hacked!")
	else:
		print("Not hacked!")






if __name__ == "__main__":
	"""	
		i use bit-flipping attack 
		to decrypt cbc-encrypted text 
		as admin=true
	"""

	bit_flipping()