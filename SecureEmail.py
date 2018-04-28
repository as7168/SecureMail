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

## Generate private and public keys using RSA
def generate_public_private_key():
	private_key_sender = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
	pem = private_key_sender.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword'))
	pem.splitlines()[0]
	file_out = open("private_key_sender.pem", "wb")
	file_out.write(pem)

	public_key_sender = private_key_sender.public_key()
	pem_pub = public_key_sender.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	pem_pub.splitlines()[0]
	file_out = open("public_key_sender.pem", "wb")
	file_out.write(pem_pub)

	private_key_receiver = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
	pem = private_key_receiver.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword'))
	pem.splitlines()[0]
	file_out = open("private_key_receiver.pem", "wb")
	file_out.write(pem)

	public_key_receiver = private_key_receiver.public_key()
	pem_pub = public_key_receiver.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	pem_pub.splitlines()[0]
	file_out = open("public_key_receiver.pem", "wb")
	file_out.write(pem_pub)

## Encrypting the plaintext message using AES GCM crypto method
def encrypt(key, plaintext, associated_data):
    # Generate a random 96-bit IV.
    iv = os.urandom(12)

    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()   
    return (iv, ciphertext, encryptor.tag)

## Encrypting the key from AES GCM using public key crypto method, RSA (receiver's public key)
def public_key_crypto_encrypt(key):
	with open("public_key_receiver.pem", "rb") as key_file1:		
		public_key = serialization.load_pem_public_key(key_file1.read(),backend=default_backend())
	enc_key = public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
	#print(enc_key)
	with open("private_key_sender.pem", "rb") as key_file2:		
		private_key = serialization.load_pem_private_key(key_file2.read(),password = b'mypassword', backend=default_backend())
	signature = private_key.sign(enc_key, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH ), hashes.SHA256())
	#print("sig: ",len(signature))
	return enc_key,signature
	
## Combining the encryption functions for encrypting the email
def EncryptedEmail(message):
	#with open("email.txt", "rb") as f:
	#	message = f.read()
	print("Message: ", message)
	aad = b"authenticated but not encrypted data"
	key = AESGCM.generate_key(bit_length=256)
	iv, ciphertext, tag = encrypt(key, message, aad)

	#Encrypt the key using RSA
	enc_key, signature = public_key_crypto_encrypt(key)
	enc_body = enc_key+signature+iv+tag+ciphertext
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
def SecureEmail(option, encrypt=False, body=None):
	if(option == 0): #generate public and private keys and store them locally
		generate_public_private_key()
	if (option == 1): # Encrypt
		enc_body = EncryptedEmail(message)
		# print(enc_body)
		file_out = open("enc_body.txt", "wb")
		file_out.write(enc_body)
		encrypt = True
		return enc_body
	if(option == 2): #Decrypt
		if encrypt == True:
			with open("enc_body.txt", "rb") as f:
				enc_body = f.read()

			#enc_body = b",n\xa1\\X\xb7\xd8\x01\xbd\x99\xdd\xf0\xed)\xd0\xf2\xb2@\xfc\x8eG\xd1\xd5\xd9\xdc}+B;\xca\x80\xe9\xa27)i\x8dN1{\x173t\x91\xa9N\xf2\xb6\xe7&\t\xbd\xc1\xcb+\x03C\xcb\x02^\xf75#@o\xa8\x9dj=H\xef>\x9aa%)0\xd7\xd5\x0c\xbb0\r\xe2\x9deEC\x90\xf4\xa00\xdc>\xcb\xfa$\xa5\xb9\xd5\x0c\xcf;\xff\xf8\xab>[n\x15\xcc\xc8\xca\xb36\xe2\xef\xae\xa0\xd8\xd4f\x0c=\xcb\xb4tE\xac\xd5\x82t\xdc\x0c\x86\xa1\x1c\x0c\xdc\xbfK\x82[\xceK~\x85;\xd2\xc5\xb5\xebP-#\xee\xb4\x86K\xcb\xdc\xf4\xb2\x07BM\x81$\x1a\xef\xfc\x03\xa3FzT+\x7f\xca\x0e(>\x91\x04n\xcb\xe61\xc9sw\xb3\x97ql\xb6\x08\xec\xbd\x1a\xaf\xaeF~\x84W\xbe.\xa1\x82\xeb\x1d\x11\xbc\xad\xc9\xa9,\x9d\xed\xaa\xd2\x9b\x11Q/\x91~\xf3\xca\xd8w\xdcMg\xfa\xe8\xdaGY\x83\xae1\r\x01b\xe1\xe2VUN\x80\xb5\xc28\xb5\xde\xbcq\xffa\xc3'\xebo\x8a\xf3*]\xa7\xdfJ\xabX.\x93\xbf\xb2R\x07\x1eC[\x06\xf4\xe3@\xbc\xaa\xb0\x8b\x91=\xc3\xde\xfb"
			pt, dec_Ver = DecryptedEmail(enc_body)
			print()
			# if dec_Ver:
			# 	print("Sender Verfied!")
			# else: 
			# 	print("Sender Not Verfied!")
			print("Decrypted Plaintext: ",pt)
		else:
			print("Error: No encrypted file found")
		return pt
## Function calls to relevant functions	
message = b'see you at 9'
SecureEmail(0)
enc_body = SecureEmail(1, message)
SecureEmail(2, True, enc_body)