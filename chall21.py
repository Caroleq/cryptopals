import time

class MTGenerator:
    """
        Class can be used to generate pseudorandom numbers
    
    """
    
    def __init__(self, size, seed=None ):
        """
            Creates MTgenerator of size `size` initialized with `seed`
        """
        if seed == None:
            seed = int( time.time() )
            
        self.__MT = [ int() for i in range(size) ]
        
        self.__MT[0] = seed
        
        for i in range(1, size ):
            tmp = 1812433253 * ( self.__MT[i-1] ^ ( self.__MT[i-1] >> 30) ) + i
            self.__MT[i] = tmp - ( ( tmp >> 32 ) << 32 )
            
        self.__index = 0
            
    def randmt( self ):
        """
            Returns pseudorandom number 
        """
        
        if self.__index == 0:
            self.__generate_series()
        
        number = self.__MT[self.__index ]
        number = number ^ ( ( number << 7 ) and 2636928640 )
        number = number ^ ( ( number << 15 ) and 4022730752 )
        number = number ^ ( number >> 18 )
        
        self.__index = ( self.__index + 1 ) % len( self.__MT )
        
        return number
    
    
    def __generate_series( self ):
        """
            Generates new series of numbers
            from existing one
        """
        
        lower_mask = ( 1 << 31 ) - 1
        upper_mask = ( ( 1 << 33) - 1 ) - lower_mask
        m = 397
        
        
        for i in range(0, len(self.__MT) ):
            tmp = self.__MT[(i+1) % len(self.__MT)] 
            y = ( self.__MT[i] and ( 1 << 31) ) + ( tmp - ( ( tmp >> 32 ) << 32 ) )
            self.__MT[i] = self.__MT[ (i + m) % len(self.__MT) ] ^ ( y >> 1)
            
            if y % 2 == 1:
                self.__MT[i] = self.__MT[i] ^ 0x9908B0DF
        
            self.__index = 0


if __name__ == "__main__":
    
    generator = MTGenerator(100)
    
    for i in range( 100 ):
        print( '[', i, ']', generator.randmt() )
