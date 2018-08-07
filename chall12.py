from random import randint
from base64 import b64decode
from Crypto.Cipher import AES
from chall8 import check_AES_ECB_line
from chall9 import pad_pkcs7
from chall15 import pkcs_unpad


class AES_ECB():
	"""
		class may encrypt text 
		with key generated for every instance of the class
	"""
	def __init__(self):
		self.__key = self.__generate_key()
		self.__cipher = AES.new(self.__key)

	def __generate_key(self):
		""" 
			generates 16 random bytes
		"""
		key = [ randint(0,255) for i in range(16) ]
		return bytes(key)

	def encrypt(self, data):
		data = pad_pkcs7(data)
		return self.__cipher.encrypt(data)

	def decrypt(self, data):
		decrypted = self.__cipher.decrypt(data)
		return pkcs_unpad( decrypted )


		

class ProxyAES():
	"""
		class for encrypting user-date
		with appended secret text
	"""

	def __init__(self, secret):
		self.__secret = secret
		self.__aes_ecb = AES_ECB()

	def encrypt(self, data):
		"""
			encrypt(data+secret)
		"""
		return self.__aes_ecb.encrypt( data + self.__secret )


class AttackECB():
	"""
		runs attack on instance of ProxyAES 
		to discover secret 
	"""

	def __init__(self, proxy_aes):
		"""
			initializes class with ProxyAES instance
		"""

		self.__proxy_aes = proxy_aes


	def run_attack(self, display_info=False):
		"""
			runs attack descibed in challenge
		"""

		block_size = self.__get_block_size()

		if display_info:
			print("Block size discovered:", block_size)

		if not self.__check_if_ecb(block_size):
			print("Cipher not in ECB mode\nExiting...")
			return

		if display_info:
			print("Function using ECB mode")

		secret = self.__exfilter_secret(block_size, display_info)

		if display_info:
			print("Secret message: ", secret.decode('utf-8'))

		return secret

	def __get_block_size(self):
		"""
			discovers block size of the cipher 
			by feeding it with additional bytes
		"""

		initial_size = len( self.__proxy_aes.encrypt( b'' ) )
		payload_size = 1
		payload = b''
		while 1==1:
			payload = bytes( [0]*payload_size )
			size = len(self.__proxy_aes.encrypt(payload))
			if size != initial_size:
				return size - initial_size
			payload_size += 1

	
	def __check_if_ecb(self, block_size):
		long_data = self.__proxy_aes.encrypt( bytes([0]*100))
		if check_AES_ECB_line(long_data, block_size):
			return True
		return False

	def __exfilter_secret(self, block_size, display_info=False):
		"""
				i decrypt secret byte-by-byte
		"""

		secret = b''

		secret_len = len( self.__proxy_aes.encrypt(b'') )

		suffix = bytes()

		i = 0
		while i < secret_len:
			secret = self.__get_next_byte(secret,   i, block_size)
			i += 1

		return secret


	def __get_next_byte(self, decrypted,  position, block_size):
		"""
			gets next byte of ciphertext


			encrypt( ( [0]*size + decrypted + ascii ) || ciphertext  )[ : len( [0]*size + decrypted + ascii)] 
			is compared to
			encrypt( ( [0]*size  ) || ciphertext  )[ : len( [0]*size + decrypted + ascii)] 
			that way we extract next byte

			len( [0]*size + decrypted + ascii) is multiple of block_size
		"""

		payload_size = block_size - 1 - len(decrypted)%block_size
		prefix = bytes( [0]*payload_size )
		cipher = self.__proxy_aes.encrypt( prefix )

		for ascii in range(256):
			payload = prefix + decrypted+ bytes([ascii])
			new_cipher = self.__proxy_aes.encrypt( payload)

			if new_cipher[:payload_size + len(decrypted) +1] == cipher[:payload_size +len(decrypted)+1]:
				return decrypted + bytes([ascii])

		return decrypted






def launch_secret():
	"""
		Creates proxy AES with secret from challenge 
		returns instance of PoxyAES class
	"""
	secret = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'\
			+'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'\
			+'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
			
	proxyAES = ProxyAES( b64decode(secret)) 

	return proxyAES



if __name__ == "__main__":
	"""
		i decrypt example from challenge page

	"""

	target = launch_secret()
	attack = AttackECB(target)
	attack.run_attack(display_info=True)