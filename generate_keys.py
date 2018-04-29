__author__ = 'nimisha'

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

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

if __name__ == '__main__':
	generate_public_private_key()
	print('sample keys generated for reciever and sender')