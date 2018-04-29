# SecurEmailS
SecurEmails is a webUI which takes in unencrypted email body and encrypts it locally before sending it on the internet. The receiver receives this encrypted data and decrypts it locally to obtain the original message.

## Installing Dependenies:
1. Cryptography part of the project uses [Cryptography](https://cryptography.io/en/latest/) python library. You can install it like:
`pip install cryptography`, pip used is for python3.

```
Install Python3
sudo apt-get install python3-pip
sudo apt-get install libssl-dev
sudo python3 -m pip install cryptography --force-reinstall
sudo python3 -m pip install flask
```
To run the application extract the zip file, cd to that directory and execute the following commands
```
sudo python3 app.py (this will run on localhost:5999)
sudo python3 decrypt_app.py (this will run on localhost:5000)
```
You will be able to access the app using a browser

## Working:
- Before running the application, you have to make sure that private and public keys are in the application folder
- A simple python script is provided to generate public and private key pairs for your convenience
- Since public keys are available to everyone, we have assumed that the sender will have reciever's public key and the reciever has sender's public key
- Make sure this exchange is done prior to running the application and the keys are stored in the application directory
- SecureEmail.py 
  1. The SecureEmail_func() function takes three arguments, 
     - option: Encrypt or decrypt;  
     - encrypt_flag: is encryption done before decrypting;    
     - message: plaintext or ciphertext
  2. The generate_public_private_key() function stores the generated keys in files on system. Before starting the encryption, exchange the public keys.
