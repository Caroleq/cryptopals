from random import randint, choice
from chall7 import AES_ECB_encrypt
from chall8 import check_AES_ECB_line
from chall9 import pad_pkcs7
from chall10 import AES_CBC


class MixedEncryption:
    """
        Class encrypting user data half in ECB mode, half in CBC (random order)
        Class info which part was encrypted in which mode during last encryption
        So user can guess the order of mode encryption
    """
    
    def __generate_key( self ):
        """
            Generates random key to encrypt data
        """
        key = [ randint(0,255) for i in range(16) ]
        return bytes(key)
    
    def __generate_random_data( self ):
        """
            Generates random data of random length
            to add before or after user_provided data
        """
        
        length = randint(1,10)
        junk = [randint(0, 255) for i in range(length) ]
        return bytes(junk)
    
    def encrypt(self, data):
        """
            Encrypts `data` in CBC and ECB
            half chosen randomly
            order of encryption is saved to self.__first_half_mode
        """
        
        self.__first_half_mode = choice(["ecb", "cbc"])
        
        key = self.__generate_key()
        
        data = self.__generate_random_data() + data + self.__generate_random_data() 
        hlf = int( len(data)/2 )
        encrypted = b''
        if self.__first_half_mode == "ecb":
            cbc = AES_CBC(key)
            encrypted = AES_ECB_encrypt( pad_pkcs7( data[: hlf ] ), key )
            encrypted += cbc.encrypt( pad_pkcs7( data[hlf:] ) )
        else:
            cbc = AES_CBC(key)
            encrypted = cbc.encrypt( pad_pkcs7( data[hlf:] ) )
            encrypted += AES_ECB_encrypt( pad_pkcs7( data[: hlf ] ), key )
            
        return encrypted
    
    
    def verify(self, guess ):
        """
            Returns True if `guess` is correct and any text has beeen encrypted
        """
        if self.__first_half_mode == None or guess != self.__first_half_mode:
            return False
        return True
            
        
        
def detect_mode(data):
    """
        Class is sending user data and trying 
        to detect ECB mode from previous challenge
    """

    me = MixedEncryption()
    ciphertext = me.encrypt(data)
    
    hlf = int( len(ciphertext)/2 )
    first = ciphertext[:hlf]
    scd = ciphertext[hlf:]
    
    if check_AES_ECB_line(first): 
        assert me.verify("ecb")
        print("ECB:CBC")
    elif check_AES_ECB_line(scd): 
        assert me.verify("cbc")
        print("CBC:ECB")
    else:
        print("Could not detect mode :(")

if __name__ == "__main__":
    """
        i control user input so 
        i can can provide long string consistiong 
        with fixed byte at each position
    """
    
    data = bytes([97]*100)
    detect_mode(data)
