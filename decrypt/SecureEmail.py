__author__ = 'Nimisha'

## importing libraries
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

## Encrypting the plaintext message using AES GCM crypto method
def encrypt(key, plaintext, associated_data):
    # Generate a random 96-bit IV.
    # print("enter0")
    iv = os.urandom(12)
    # print("enter1")
    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    # print("enter2")
    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)
    # print("enter3")
    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()   
    # print("enter4")
    return (iv, ciphertext, encryptor.tag)

## Encrypting the key from AES GCM using public key crypto method, RSA (receiver's public key)
def public_key_crypto_encrypt(key):
	# Encrypting first with Sender's private key
	with open("public_key_receiver.pem", "rb") as key_file1:		
		public_key = serialization.load_pem_public_key(key_file1.read(),backend=default_backend())
	enc_key = public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

	# Encrypting later with Receiver's public key
	with open("private_key_sender.pem", "rb") as key_file2:		
		private_key = serialization.load_pem_private_key(key_file2.read(),password = b'mypassword', backend=default_backend())
	signature = private_key.sign(enc_key, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH ), hashes.SHA256())
	
	return enc_key,signature
	
## Combining the encryption functions for encrypting the email
def EncryptedEmail(message):
	#with open("email.txt", "rb") as f:
	#	message = f.read()
	print("Message: ", message)
	aad = b"authenticated but not encrypted data"
	key = AESGCM.generate_key(bit_length=256)
	# print("entered")
	# print(key)
	# print(message)
	# print(aad)
	iv, ciphertext, tag = encrypt(key, message, aad)
	# print("exit")
	#Encrypt the key using RSA
	enc_key, signature = public_key_crypto_encrypt(key)
	enc_body = enc_key+signature+iv+tag+ciphertext
	#print("enc_body: ", enc_body)
	#print("ciphertext: ",ciphertext)
	return enc_body

## Decrypting the encrypted AES key using private key
def public_key_crypto_decrypt(enc_key, signature, private_key, public_key):
	dec_ver = public_key.verify(signature, enc_key,padding.PSS( mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH ), hashes.SHA256() )
	#print(dec_ver)
	dec_key = private_key.decrypt(enc_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

	return dec_key,dec_ver

## Decrypting the ciphertext using decrypted AES key
def decrypt(key, associated_data, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()

def attack(enc_body):
	#private_key = public_key_crypto_load()
	with open("public_key_sender.pem", "rb") as key_file1:		
		public_key = serialization.load_pem_public_key(key_file1.read(),backend=default_backend())
	with open("private_key_sender1.pem", "rb") as key_file2:
		private_key1 = serialization.load_pem_private_key( key_file2.read(), password=b'mypassword', backend=default_backend())
	
	enc_key_part = enc_body[:256]
	signature = enc_body[256:512]
	iv = enc_body[256+256:268+256]
	tag = enc_body[268+256:284+256]
	ct_part = enc_body[284+256:]

	signature = private_key1.sign(enc_key_part, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH ), hashes.SHA256())
	enc_body = enc_key_part+signature+iv+tag+ct_part
	return enc_body

## Combining the decryption functions for decrypting the email
def DecryptedEmail(enc_body):
	#private_key = public_key_crypto_load()
	with open("public_key_sender.pem", "rb") as key_file1:		
		public_key = serialization.load_pem_public_key(key_file1.read(),backend=default_backend())
	with open("private_key_receiver.pem", "rb") as key_file2:
		private_key = serialization.load_pem_private_key( key_file2.read(), password=b'mypassword', backend=default_backend())
	
	enc_key_part = enc_body[:256]
	signature = enc_body[256:512]
	iv = enc_body[256+256:268+256]
	tag = enc_body[268+256:284+256]
	ct_part = enc_body[284+256:]
	dec_key, dec_ver = public_key_crypto_decrypt(enc_key_part, signature, private_key,public_key)
	plaintext = decrypt(dec_key, b"authenticated but not encrypted data", iv, ct_part, tag)
	return plaintext, dec_ver

## Main function for generation of key pairs, encryption, and decryption selection	
def SecureEmail_func(option, encrypt=False, message=None):
	if (option == 1): # Encrypt
		enc_body = EncryptedEmail(message)
		# print(enc_body)
		file_out = open("enc_body.txt", "wb")
		file_out.write(enc_body)
		encrypt = True
		return encrypt, enc_body
	if(option == 2): #Decrypt
		if encrypt == True:
			# with open("enc_body.txt", "rb") as f:
			# 	enc_body = f.read()

			#enc_body =   b'\x194\x14\xd8\x8a\xc1\xe2 \x83\xa5\xda@\x1a4\xc9\x84\xee&\xb9/\xe20\x05\n \x18R\xf8p\xcf\xa6r|\xd4e\xed\xbd\xb4\x81\xb3[0$\xf1\xa6r\xacW:\xfc\xd50\xab\x1bJ\x8bs\x91\x98\xe4c\x9af\xfe\x87\x99N\x8b\xc3\x99\xae\x92\xd0T\x0eE\xbb\xed\xfa\x1d\x03\xfa\xf9\xc1\x92\xe0"k\xf8g\xd9e\xcaH\x14\xa6\xca\x1c\n$m\xb2j\xc6\xec\xe3~\xb9B\xb4\x89\xc5\xa9\x04\x08\xbd\xe2\x88\xff\xd2\x87\xb3\xc8^\xa0\x93(!o\xaaM}g\x81*\xe3\x88\xdf\xe4\xb43\xcf\xefT\xbac\xdd\xdf\xc5g\xa1>m\xfa\xcc\x95\x14B\xde3@\xa5\xf163\xdc\xab\xafV?\x9fU\xc5\x95\x9b\x0fC\x10f\xee\xb7\x85x\x16\xb5\x15\xba\xb9\xa9/:\x18Y\xcb\x12\xc5eIy\xdf\x86\t\x18\xad\xf13x\xa8\xb0\xda\xf1\x02rI\x01/~1\xe2h\x8a\xfd\xb7\xcd\xeb\xb7\xd2\xc6\x07\x90\xdc\x9f8M\x11\xfc\x9d\xca\x97J/\x9e\x0e\x9d\x03o97aF\x8a\xe9g\xb6}\x12!\xb5;\xd8&8i\xfc4\xb7\xf8\xed\x1b\xb8\xb9\n\xe8\xe7\x9c3\xe7\xb7\x98l\xe0\x8a)O\xd9\x98w^\xa0<3\x85\xb5@\xe1\x81\x05\xaa\x0fUd\xcb\x90\x1e\xd7+\x83;Q\xa3%N\xfa\xa1\xf7G\xe2Y,\xd0\xfd8\xe3\x0c2k\xa9qJ%\xa8\x0ex\x85A%\xb9&Z\x80U\x9a\xd3\r\x0bu\xa9L\x9a\xfb\xb8\xbd\x8d\x9d\x06A^k\xc6|\xbb\x12E\xec\xb1/\xef\xc2\xc2>,\x05*M\xcc\x19\xa26<\xed\xfa\xe2\xb1\xcd\xdbD\xdc\xd0\x0f,M#K\x87\xf0.@Np\x13\xc9\xab\xa84\xd9,q\xd7\x9f\xb5\xa0\xd5\x04\x8e\x04\x91\xc5\xe7j\x1e3IX\x155\x03\x8cB\x16T\x13"W\x03\x1e\x03f<\xf9-\x94\x16\xc6p\xab%\xb0u\xbb\xad\xa81\xbe|\xbe\x80v\x8a*\x89&N|\xd54\x8b\xfd)\xcd)\x98\xf4\xe2\x0b\xc5V_\xff\xbbr0\x8db\x9dck\xd3v\xcf\x92\xb9\x00\xfaw\xc8D\xdfH\xa0u\xe1l\xaa\xd0N\xb7p\x9cCP\xe5\x8d\x1bkd@\x91\x87Xb\xe6\xfe\xdb\xa9\xab\x04\xb1\xaec\x82X\xc5\xee\xad$ Uk\xb2\xe7\xf5w\x90\x046\xa5v\xfcnm\xc9>'
			pt, dec_Ver = DecryptedEmail(message)
			print()
			print("Decrypted Plaintext: ",pt)
		else:
			print("Error: No encrypted file found")
		return pt
	if(option==3): # Attack against non-repudiation
		if encrypt == True:
			#print("entered")
			with open("enc_body.txt", "rb") as f:
				enc_body = f.read()
			enc_body1 = attack(enc_body)
			pt, dec_Ver = DecryptedEmail(enc_body1)
			print()
			print("Decrypted Plaintext: ",pt)
## Function calls to relevant functions	

# message = b'see you at 8'
# message1 = b'see you at 9'

# SecureEmail_func(0)
# encrypt_flag, enc_body = SecureEmail_func(1,False, message)
# SecureEmail_func(2, encrypt_flag, enc_body)
# SecureEmail_func(0)
# encrypt_flag, enc_body = SecureEmail_func(1,False, message1)
# SecureEmail_func(2, encrypt_flag, enc_body)
# # SecureEmail_func(3, encrypt, enc_body)
