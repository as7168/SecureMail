## importing libraries
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP

## Generate private and public keys using RSA
def generate_private_key():
	key = RSA.generate(2048)
	private_key = key.export_key()
	file_out = open("private_key.pem", "wb")
	file_out.write(private_key)
	#return private_key
	
## Loading Private key from PEM file	
def public_key_crypto_load():
	with open("private_key.pem", "rb") as key_file:
		private_key = serialization.load_pem_private_key( key_file.read(), password=None, backend=default_backend())
	#print("private_key: ", private_key)	
	pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())

	pem.splitlines()[0]
	#print(pem)
	public_key = private_key.public_key()
	pem_pub = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	pem_pub.splitlines()[0]
	#print(pem_pub)
	file_out = open("public_key.pem", "wb")
	file_out.write(pem_pub)
	return private_key

## Encrypting the plaintext message using AES GCM crypto method
def symmetric_key_crypto_encrypt(message):
	data = message #"a secret message"
	#aad = b"authenticated but unencrypted data"
	key = AESGCM.generate_key(bit_length=128)
	aesgcm = AESGCM(key)
	nonce = os.urandom(12)
	ct = aesgcm.encrypt(nonce, data, None)
	
	return ct, key, nonce

## Encrypting the key from AES GCM using public key crypto method, RSA
def public_key_crypto_encrypt(key):
	with open("public_key.pem", "rb") as key_file:		
		public_key = serialization.load_pem_public_key(key_file.read(),backend=default_backend())
	enc_key = public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
	#print("encrypted_key: ", enc_key)
	return enc_key
	
## Combining the encryption functions for encrypting the email
def EncryptedEmail():
	with open("email.txt", "rb") as f:
	#email = "Some email text"
		message = f.read()
	print("Message: ", message)
	# Generate Public and Private keys
	#_ = public_key_crypto_load()
	
	#Encrypt the message using AESGCM method
	ct, key, nonce = symmetric_key_crypto_encrypt(message)

	#Encrypt the key using RSA
	enc_key = public_key_crypto_encrypt(key)
	#print("enc_key: ", enc_key)
	#print("Ciphertext: ",ct)
	return ct, enc_key, nonce

	

## Decrypting the encrypted AES key using private key
def public_key_crypto_decrypt(enc_key, private_key):
	#print(enc_key)
	dec_key = private_key.decrypt(enc_key,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
	return dec_key

## Decrypting the ciphertext using decrypted AES key
def symmetric_key_crypto_decrypt(dec_key, ct, nonce):
	aesgcm_dec = AESGCM(dec_key)
	plaintext = aesgcm_dec.decrypt(nonce, ct, None)
	print("Plaintext: ",plaintext)
	return plaintext
	
## Combining the decryption functions for decrypting the email
def DecryptedEmail(ct, enc_key, nonce):
	private_key = public_key_crypto_load()
	dec_key = public_key_crypto_decrypt(enc_key, private_key)
	plaintext = symmetric_key_crypto_decrypt(dec_key, ct,nonce)


## Main function for generation of key pairs, encryption, and decryption selection	
def SecureEmail(option, ct, enc_key, nonce, encrypt):
	if(option == 0): #generate public and private keys and store them locally
		generate_private_key()
		_ = public_key_crypto_load()
	if (option == 1): # Encrypt
		ct, enc_key, nonce = EncryptedEmail()
		encrypt = True
		return ct, enc_key, nonce, encrypt
	if(option == 2): #Decrypt
		if encrypt == True:
			pt = DecryptedEmail(ct, enc_key, nonce)
		else:
			print("Error: Encrypt first to decrypt")
			
#ct, enc_key, nonce = EncryptedEmail()		
#DecryptedEmail(ct, enc_key, nonce)	

## Fucntion calls to relevant functions	
SecureEmail(0,None,None,None,None)
ct, enc_key, nonce, encrypt = SecureEmail(1,None,None,None,None)
SecureEmail(2,ct, enc_key, nonce, encrypt)