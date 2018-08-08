from random import randint
from Crypto.Cipher import AES
import json
from chall9 import pad_pkcs7
from chall15 import pkcs_unpad

class Parser:
	"""
		Class converting routine 
		encoded e.g. param1=value1&param2=value2
		to dictionary object:
		{
			"param1":"value1",
			"param2":"value2"
		}
	"""


	def parse(self, routine ):
		"""
			parses routine
		"""
		dictionary = dict()

		for item in routine.split('&'):
			param, value = item.split('=')
			dictionary[param] = value

		return dictionary



class Account:
	"""
		Creates routine from provided email. Then creates dictionary
		from this routine. Cipher of routine is publicly available.
		Class provides funtionality of creating another account based on ciphertext 
		provided by user.
		
	"""

	__Uuid = 0
	__Cipher = None

	def __init__(self, email):
		"""
			Creates account from email
		"""

		email = email.replace("=","").replace("&","")
		email = str.encode(email)
		routine = b'email='+ email + b'&uuid=' + str.encode( str(self.__Uuid) ) + b'&role=user'

		self.parser = Parser()
		self.__account_data = self.parser.parse(routine.decode('utf-8')) 

		Account.__Uuid += 1
		if self.__Cipher == None:
			key = self.generate()
			Account.__Cipher = AES.new( key, AES.MODE_ECB)

		self.__cbc_routine = self.__Cipher.encrypt( pad_pkcs7(routine) )



	def generate(self):
		"""
			Generates random bytes - for __Key
		"""
		key = [ randint(0, 255) for i in range(16)]
		return bytes(key)

	def get_cipher(self):
		"""
			returns cipher-encrypted profile routine
		"""
		return self.__cbc_routine 

	def  generate_account(self, ciphertext):
		"""
			decrypts user-provided text 
			converts routine to dictionary 
			and returns that dictionary
		"""

		decrypted = Account.__Cipher.decrypt( ciphertext )
		decrypted = pkcs_unpad(decrypted)

		account = self.parser.parse( decrypted.decode('utf-8') )
		return account



def attack():
	"""
		Function runs attack on `Account` class and generates ciphertext
		which provides us with dictonary with elevated user priviledges 
	"""

	# the string `email=[email]` will occupy exactly 32 bytes
	# it will look like  [email=anything_to_16_bytes][admin + '\x11'*16]
	# thus we will obtain cipherblock of padd(admin)
	payload = ( 16 - len('email=') )*'A' + pad_pkcs7('admin')
	account1 = Account( payload )
	cipher_from_payload = account1.get_cipher()

	# this is cipher( padd(admin) )
	admin_priviledge = cipher_from_payload[16:32]

	# i compute email length so 
	# email=[email]&uuid=[uuid]&role= occupies exactly 2 blocks
	# i assume uuid has value less then 10
	new_account_len = 'A'*(16*2-len('email=') - len('&uuid=X&role='))

	account2 = Account(new_account_len)
	cipher_to_modify = account2.get_cipher()

	# now i can swap last block to decode to admin+'\x11'*11
	ciper_payload = cipher_to_modify[:32] + admin_priviledge
	d = account2.generate_account( ciper_payload)
	print( d )

if __name__ == "__main__":
	"""
		Exploits above encryption system
	"""

	attack()

	