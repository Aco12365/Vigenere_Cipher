"""
-----------------------------
CP460 (Fall 2021)
Name: Aleksandar Stojanovic
ID:   190265090
Assignment 4
-----------------------------
"""

"""Put any comments to the grader here"""

from os import PathLike, supports_bytes_environ
from typing import NewType
import utilities

class Cryptanalysis:
    """
    ----------------------------------------------------
    Description: Class That contains cryptanalysis functions
                 Mainly for Vigenere and Shift Cipher 
                     but can be used for other ciphers
    ----------------------------------------------------
    """
    @staticmethod    
    def index_of_coincidence(text,base_type = None):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   text(str)
                      base_type(str): default = None
        Return:       I (float): Index of Coincidence
        Description:  Computes and returns the index of coincidence 
                      Uses English alphabets by default, otherwise, given base_type
        Asserts:      text is a string
        ----------------------------------------------------
        """
        assert type(text)== str
        
        text = text.lower()
        tempText = ''

        if base_type == None:
                base_type = 'lower'

        base = utilities.get_base(base_type)

        for j in text:
            if(j in base):
                tempText+=j

        freqs = utilities.get_freq(tempText,base);
        total = len(tempText)
        ioc = 0.0

        
        if (total>0):
            for i in range(len(base)):
                ioc+= (freqs[i] * (freqs[i]-1))
            ioc = ioc/(total*(total-1))
        
        return ioc      

    @staticmethod
    def IOC(text):
        """
        ----------------------------------------------------
        Same as Cryptanalysis.index_of_coincidence(text)
        ----------------------------------------------------
        """
        return Cryptanalysis.index_of_coincidence(text)
    
    @staticmethod
    def friedman(ciphertext):
        """
        ----------------------------------------------------
        Static method
        Parameters:   ciphertext(str)
        Return:       list of two key lengths [int,int]
        Description:  Uses Friedman's test to compute key length
                      returns best two candidates for key length
                        Best candidates are the floor and ceiling of the value
                          Starts with most probable key, for example: 
                          if friedman = 3.2 --> [3, 4]
                          if friedman = 4.8 --> [5,4]
                          if friedman = 6.5 --> [6, 5]
        Asserts:      ciphertext is a non-empty string
        ----------------------------------------------------
        """
        base = utilities.get_base('lower')
        ciphertext = ciphertext.lower()
        n = 0

        for j in ciphertext:
            if (j in base):
                n+=1
        i = Cryptanalysis.IOC(ciphertext)
        low = 0.0385
        high = 0.065
        friedman = (0.0265*n)/((high-i) + (n*(i-low)))
        intFriedman = int(friedman)

        if ((friedman+0.5) < intFriedman+1):
            return [intFriedman,intFriedman+1]
        else:
            return [intFriedman+1,intFriedman]

    @staticmethod
    def chi_squared(text,language='English'):
        """
        ----------------------------------------------------
        Parameters:   text (str)
                      language (str): default = 'English'
        Return:       result (float)
        Description:  Calculates the Chi-squared statistics 
                      for given text against given language
                      Only alpha characters are considered
        Asserts:      text is a string
        Errors:       if language is unsupported:
                        print error msg: 'Error(chi_squared): unsupported language'
                        return -1
        ----------------------------------------------------
        """
        assert type(text) == str

        base = utilities.get_base('lower')
        langFreqs = utilities.get_language_freq(language)

        size = 0

        for chr in text.lower():
            if chr in base:
                size+=1

        if langFreqs == [] or text == '' or size == 0:
            return -1
        
        textFreqs = utilities.get_freq(text.lower(), base)
        chi = 0.0
        for i in range(len(textFreqs)):
            e = langFreqs[i]*size
            chi+=(( textFreqs[i] - e)*( textFreqs[i] - e))/e

        return chi

    @staticmethod
    def cipher_shifting(ciphertext,args =[20,26]):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
                      args (lsit):
                          max_key_length (int): default = 20
                          factor (int): default = 26
        Return:       Best two key lengths [int,int]
        Description:  Uses Cipher shifting to compute key length
                      returns best two candidates for key length
                      cipher shift factor determines how many shifts should be made
                      Cleans the text from all non-alpha characters before shifting
                      Upper and lower case characters are considered different chars
                      The returned two keys, are the ones that produced highest matches
                          if equal, start with smaller value
        Asserts:      ciphertext is a non-empty string
        ----------------------------------------------------
        """
        assert type(ciphertext) == str and len(ciphertext) > 0
        base = utilities.get_base('alpha')

        maxKey = args[0]
        factor = args[1]
        
        tempText  = ''
        for chr in ciphertext:
            if chr in base:
                tempText+=chr

        lis = []
        for f in range(1,factor):
            NewText = (' '*f) + tempText[0:len(tempText)-f]
            matches = 0
            for i in range(len(tempText)):
                if tempText[i] == NewText[i]:
                    matches+=1
            lis.append(matches)

      
        max1 = lis.index(max(lis)) + 1
        lis[max1-1] = 0
        if (max1 > maxKey):
            max1 = max1%maxKey
  
        max2 = lis.index(max(lis)) + 1
        if (max2 > maxKey):
            max2 = max2%maxKey
   
        return [max1,max2]

class Shift:
    """
    ----------------------------------------------------
    Cipher name: Shift Cipher
    Key:         (int,int,int): shifts,start_index,end_index
    Type:        Shift Substitution Cipher
    Description: Generalized version of Caesar cipher
                 Uses a subset of BASE for substitution table
                 Shift base by key and then substitutes
                 Case sensitive
                 Preserves the case whenever possible
                 Uses circular left shift
    ----------------------------------------------------
    """
    BASE = utilities.get_base('all') + ' '
    DEFAULT_KEY = (3,26,51)   #lower case Caesar cipher
    
    def __init__(self,key=DEFAULT_KEY):
        """
        ----------------------------------------------------
        Parameters:   _key (int,int,int): 
                        #shifts, start_index, end_indx 
                        (inclusive both ends of indices)
        Description:  Shift constructor
                      sets _key
        ---------------------------------------------------
        """
        if self.valid_key(key):
            if (key[0]< 0):
                
                key1 = ((key[2]-key[1])+1)+key[0]
                self._key = (key1,key[1],key[2])
            else:
                self._key = key
        else:
            self._key = self.DEFAULT_KEY
    
    def get_key(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       key (str)
        Description:  Returns a copy of the Shift key
        ---------------------------------------------------
        """
        return self._key
       
    def set_key(self,key):
        """
        ----------------------------------------------------
        Parameters:   key (str): non-empty string
        Return:       success: True/False
        Description:  Sets Shift cipher key to given key
                      #shifts is set to smallest value
                      if invalid key --> set to default key
        ---------------------------------------------------
        """ 
        if self.valid_key(key):
            if (key[0]<0):
                key1 = ((key[2]-key[1])+1)+key[0]
                self._key = (key1,key[1],key[2])
            else:
                self._key = key
            return True
        else:
            self._key = self.DEFAULT_KEY
            return False

    def get_base(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       base (str)
        Description:  Returns a copy of the base characters
                      base is the subset of characters from BASE
                      starting at start_index and ending with end_index
                      (inclusive both ends)
        ---------------------------------------------------
        """

        return self.BASE[self._key[1]:self._key[2]+1]
        
    def __str__(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       output (str)
        Description:  Constructs and returns a string representation of 
                      Shift object. Used for testing
                      output format:
                      Shift Cipher:
                      key = <key>
                      base = <base>
                      sub  = <sub>
        ---------------------------------------------------
        """
        key = self._key
        base = self.get_base()
        sub = utilities.shift_string(base,key[0])
        return 'Shift Cipher:\nkey = {}\nbase = {}\nsub  = {}'.format(key,base,sub)
    
    @staticmethod
    def valid_key(key):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   key (?):
        Returns:      True/False
        Description:  Checks if given key is a valid Shift key
                      A valid key is a tuple consisting of three integers
                          shifts, start_index, end_index
                      The shifts can be any integer
                      The start and end index should be positive values
                      such that start is smaller than end and both are within BASE
        ---------------------------------------------------
        """
        if type(key) == tuple and len(key) == 3:
            if type(key[0]) == int and type(key[1]) == int and type(key[2]) == int:
                if key[1] < key[2]:
                    if key[1] >= 0 and key[2] <=len(Shift.BASE):
                        return True
        return False

    def encrypt(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Encryption using Shift Cipher
        Asserts:      plaintext is a string
        ---------------------------------------------------
        """

        assert type(plaintext) == str

        shifts = self._key[0]
        base = self.get_base()
        sub = utilities.shift_string(base,shifts)
        ciphertext = ''

        for char in plaintext:
            if char in base:
                i = base.index(char)
                ciphertext+=sub[i]
            else: 
                ciphertext+=char
        
    
        return ciphertext

    def decrypt(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Decryption using Shift Cipher
        Asserts:      ciphertext is a string
        ---------------------------------------------------
        """
        assert type(ciphertext) == str

        shifts = self._key[0]
        base = self.get_base()
        sub = utilities.shift_string(base,shifts)
        plaintext = ''

        for char in ciphertext:
            if char in sub:
                i = sub.index(char)
                plaintext+=base[i]
            else:
                plaintext+=char
        
        return plaintext

    @staticmethod
    def cryptanalyze(ciphertext,args=['',-1,0]):
        """
        ----------------------------------------------------
        Static method
        Parameters:   ciphertext (string)
                      args (list):
                            base: (str): default = ''
                            shifts: (int): default = -1
                            base_length (int): default = -1 
        Return:       key,plaintext
        Description:  Cryptanalysis of Shift Cipher
                      Returns plaintext and key (shift,start_indx,end_indx)
                      Uses the Chi-square method
                      Assumes user passes a valid args list
        ---------------------------------------------------
        """
        base = args[0]
        base_length = args[2]
        cryptanalysis = Cryptanalysis()
        shift = Shift()

        if base == '':
            base = shift.BASE
        else:
            base_length = len(base)
          
        minkey = (0,0,base_length)
        shift.set_key(minkey)
        minplaintext = shift.decrypt(ciphertext)
        minchi = cryptanalysis.chi_squared(minplaintext)
        for s in range(0,base_length):
            for x in range(len(base)):
                key = (s,x,x+base_length-1)
                shift.set_key(key)
                plaintext = shift.decrypt(ciphertext)
                chi = cryptanalysis.chi_squared(plaintext)
                #print('shifts: {}, base: {}, chi: {}'.format(s,shift.get_base(),chi))
                if (chi < minchi):
                    minchi = chi
                    minkey = key
                    minplaintext = plaintext

        return minkey,minplaintext

class Vigenere:
    """
    ----------------------------------------------------
    Cipher name: Vigenere Cipher
    Key:         (str): a character or a keyword
    Type:        Polyalphabetic Substitution Cipher
    Description: if key is a single characters, uses autokey method
                    Otherwise, it uses a running key
                 In autokey: key = autokey + plaintext (except last char)
                 In running key: repeat the key
                 Substitutes only alpha characters (both upper and lower)
                 Preserves the case of characters
    ----------------------------------------------------
    """

    DEFAULT_KEY = 'k'
    
    def __init__(self,key=DEFAULT_KEY):
        """
        ----------------------------------------------------
        Parameters:   _key (str): default value: 'k'
        Description:  Vigenere constructor
                      sets _key
                      if invalid key, set to default key
        ---------------------------------------------------
        """
        tempKey = ''
        if self.valid_key(key):
            for chr in key:
                if chr.isalpha():
                    tempKey+=chr.lower()
            self._key = tempKey;
        else:
            self._key = self.DEFAULT_KEY
    
    def get_key(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       key (str)
        Description:  Returns a copy of the Vigenere key
        ---------------------------------------------------
        """
        return self._key
       
    def set_key(self,key):
        """
        ----------------------------------------------------
        Parameters:   key (str): non-empty string
        Return:       success: True/False
        Description:  Sets Vigenere cipher key to given key
                      All non-alpha characters are removed from the key
                      key is converted to lower case
                      if invalid key --> set to default key
        ---------------------------------------------------
        """ 
        tempKey = ''
        if self.valid_key(key):
            for chr in key:
                if chr.isalpha():
                    tempKey+=chr.lower()
            self._key = tempKey;
            return True
        else:
            self._key = self.DEFAULT_KEY
            return False
    
    def __str__(self):
        """
        ----------------------------------------------------
        Parameters:   -
        Return:       output (str)
        Description:  Constructs and returns a string representation of 
                      Vigenere object. Used for testing
                      output format:
                      Vigenere Cipher:
                      key = <key>
        ---------------------------------------------------
        """
        return 'Vigenere Cipher:\nkey = {}'.format(self._key)
    
    @staticmethod
    def valid_key(key):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   key (?):
        Returns:      True/False
        Description:  Checks if given key is a valid Vigenere key
                      A valid key is a string composing of at least one alpha char
        ---------------------------------------------------
        """
        if type(key) == str:
            for chr in key:
                if chr.isalpha():
                    return True
        return False

    @staticmethod
    def get_square():
        """
        ----------------------------------------------------
        static method
        Parameters:   -
        Return:       vigenere_square (list of string)
        Description:  Constructs and returns vigenere square
                      The square contains a list of strings
                      element 1 = "abcde...xyz"
                      element 2 = "bcde...xyza" (1 shift to left)
        ---------------------------------------------------
        """
        base = utilities.get_base('lower')
        size = len(base)
        vSqaure = []
        for x in range(size):
            vSqaure.append(utilities.shift_string(base,x))
        return vSqaure

    def encrypt(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Encryption using Vigenere Cipher
                      May use an auto character or a running key
        Asserts:      plaintext is a string
        ---------------------------------------------------
        """
        assert type(plaintext) == str, 'invalid plaintext'
        
        if len(self._key) == 1:
            return self._encrypt_auto(plaintext)
        else:
            return self._encrypt_run(plaintext)

    def _encrypt_auto(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Private helper function
                      Encryption using Vigenere Cipher Using an autokey
        ---------------------------------------------------
        """
        base = ' \n\t' + utilities.get_base("nonalpha")
        whiteSpace = utilities.get_positions(plaintext,base)
        square = self.get_square()

        ciphertext = ''
        tempPlaintext=''

        for chr in plaintext:
            if chr not in base:
                tempPlaintext+=chr
        
        subText = self._key + tempPlaintext[0:len(tempPlaintext)-1]

        for x in range(len(subText)):
            colChr = tempPlaintext[x].lower()
            rowChr = subText[x].lower()

            row = ord(rowChr) - ord('a')
            col = ord(colChr) - ord('a')
            sub = square[row][col] if tempPlaintext[x].islower() else square[row][col].upper()

            ciphertext += sub

        ciphertext = utilities.insert_positions(ciphertext,whiteSpace)
        return ciphertext

    def _encrypt_run(self,plaintext):
        """
        ----------------------------------------------------
        Parameters:   plaintext (str)
        Return:       ciphertext (str)
        Description:  Private helper function
                      Encryption using Vigenere Cipher Using a running key
        ---------------------------------------------------
        """

        base = ' \n\t' + utilities.get_base("nonalpha")
        whiteSpace = utilities.get_positions(plaintext,base)
        square = self.get_square()

        ciphertext = ''
        tempPlaintext=''

        for chr in plaintext:
            if chr not in base:
                tempPlaintext+=chr
        
        subText = ''
        tempCount = 0
        for _ in range(len(tempPlaintext)):
            if tempCount >= len(self._key):
                tempCount=0
            subText+=self._key[tempCount]
            tempCount+=1
        
        for x in range(len(subText)):
            colChr = tempPlaintext[x].lower()
            rowChr = subText[x].lower()

            row = ord(rowChr) - ord('a')
            col = ord(colChr) - ord('a')

            sub = square[row][col] if tempPlaintext[x].islower() else square[row][col].upper()
            
            ciphertext += sub

        ciphertext = utilities.insert_positions(ciphertext,whiteSpace)
        return ciphertext

    def decrypt(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Decryption using Vigenere Cipher
                      May use an auto character or a running key
        Asserts:      ciphertext is a string
        ---------------------------------------------------
        """
        assert type(ciphertext) == str, 'invalid input'
        
        if len(self._key) == 1:
            return self._decryption_auto(ciphertext)
        else:
            return self._decryption_run(ciphertext)

    def _decryption_auto(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Private Helper method
                      Decryption using Vigenere Cipher Using autokey
        ---------------------------------------------------
        """
        base = ' \n\t' + utilities.get_base("nonalpha")
        whiteSpace = utilities.get_positions(ciphertext,base)
        square = self.get_square()

        key = self._key
        plaintext = ''
        tempCiphertext=''

        for chr in ciphertext:
            if chr not in base:
                tempCiphertext+=chr

        for char in tempCiphertext:
            rowChr = key
            row = ord(rowChr) - ord('a')
            
            col = square[row].index(char.lower())
            colChar = square[0][col] if tempCiphertext.islower() else square[0][col].upper()

            plaintext+=colChar

            key = colChar.lower()
    
        plaintext = utilities.insert_positions(plaintext,whiteSpace)
        return plaintext

    def _decryption_run(self,ciphertext):
        """
        ----------------------------------------------------
        Parameters:   ciphertext (str)
        Return:       plaintext (str)
        Description:  Private Helper method
                      Decryption using Vigenere Cipher Using running key
        ---------------------------------------------------
        """
        base = ' \n\t' + utilities.get_base("nonalpha")
        whiteSpace = utilities.get_positions(ciphertext,base)
        square = self.get_square()

        plaintext = ''
        tempCiphertext=''

        for chr in ciphertext:
            if chr not in base:
                tempCiphertext+=chr
        
        subText = ''
        tempCount = 0
        for _ in range(len(tempCiphertext)):
            if tempCount >= len(self._key):
                tempCount=0
            subText+=self._key[tempCount]
            tempCount+=1

        for i in range(len(tempCiphertext)):
            rowChr = subText[i]
            row = ord(rowChr) - ord('a')
            
            col = square[row].index(tempCiphertext[i].lower())
            colChar = square[0][col] if tempCiphertext[i].islower() else square[0][col].upper()

            plaintext+=colChar

    
        plaintext = utilities.insert_positions(plaintext,whiteSpace)
        return plaintext

    
    @staticmethod
    def cryptanalyze_key_length(ciphertext):
        """
        ----------------------------------------------------
        Static Method
        Parameters:   ciphertext (str)
        Return:       key_lenghts (list)
        Description:  Finds key length for Vigenere Cipher
                      Combines results of Friedman and Cipher Shifting
                      Produces a list of key lengths from the above two functions
                      Start with Friedman and removes duplicates
        ---------------------------------------------------
        """
        cryptanalysis = Cryptanalysis()

        shift = cryptanalysis.cipher_shifting(ciphertext)
        friedman = cryptanalysis.friedman(ciphertext)

        lengths = []

        for x in friedman:
            lengths.append(x)
        for y in shift:
            if y not in lengths:
                lengths.append(y)

        return lengths

    @staticmethod
    def cryptanalyze(ciphertext):
        """
        ----------------------------------------------------
        Static method
        Parameters:   ciphertext (string)
        Return:       key,plaintext
        Description:  Cryptanalysis of Shift Cipher
                      Returns plaintext and key (shift,start_indx,end_indx)
                      Uses the key lengths produced by Vigenere.cryptanalyze_key_length
                      Finds out the key, then apply chi_squared
                      The key with the lowest chi_squared value is returned
        Asserts:      ciphertext is a non-empty string
        ---------------------------------------------------
        """
        vigenere = Vigenere()
        shift = Shift()
        baseNon = utilities.get_base('nonalpha') + ' \t\n' 
        base = utilities.get_base('lower')
        ciphertextTemp = utilities.clean_text(ciphertext,baseNon).lower()

        keys=[]
        lengths = vigenere.cryptanalyze_key_length(ciphertextTemp)
        for length in lengths:
            key = ""
            if length > 1:
                blocks = utilities.text_to_blocks(ciphertextTemp,length,padding=True)
                baskets = utilities.blocks_to_baskets(blocks)
                for basket in baskets:
                    k,_= shift.cryptanalyze(basket,[base,-1,length])
                    key+=base[k[0]]
                keys.append(key)
            else:
                continue
            
        
        for k in keys:
            vigenere.set_key(k)
            plaintext = vigenere.decrypt(ciphertext)
            if utilities.is_plaintext(plaintext,utilities.load_dictionary('engmix.txt'),0.85):
                return k,plaintext



        return "",''

        