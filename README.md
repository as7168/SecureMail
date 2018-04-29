# SecurEmailS
SecurEmails is a webUI which takes in unencrypted email body and encrypts it locally before sending it on the internet. The receiver receives this encrypted data and decrypts it locally to obtain the original message.

## Installing Dependenies:
1. Cryptography part of the project uses Cryptography python library. You can install it like:
`pip install cryptography`, pip used is for python3.

## Working:
- SecureEmail.py 

1. The SecureEmail_func() function takes three arguments, 
--option: generate RSA keys, Encrypt, or decrypt; 
--encrypt_flag: is encryption done before decrypting; 
--message: plaintext or ciphertext
 
 2. The generate_public_private_key() function stores the generated keys in files on system. Before starting the encryption, exchange the public keys.
