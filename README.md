# SecureMail
WebUI to encrypt/decrypt and send/receive emails


# Initial thoughts

So What I have in mind is one WebUI where a user can input the email address/addresses, mail subject and body of the email. Send the email. Our program will encrypt the mail and send it using user's email ID (which he will provide during configuration of the application) to the email/emails that he provided in the webUI.

Another WebUI which will get the email from the user's email account and decrypt the encrypted email and display the content.(I need to figure out the details of this step) 

This way, the email provider (gmail/yahoo/etc) wont traverse the email as plaintext but ciphertext through their servers prevent data leakage (confidentiality). 
## nimisha
You can work on this ^ if you like - what are the cryptic advantages this method provides? how is this helpful?

Another thing that I would like you to work on is what kind of crypto should we use in this, since I have not been paying as much attention in the class, you would have a better idea on this. So we need to encrypt email subject and body, decrypt it on another host.


## Questions:
1. WebUI will have inputs as senders' email address, subject and the body. The WebUI application will takes these inputs and encrypt the subject and the body of the email. Then send to the email address, the encrypted subject and body. The same WebUI at the server end (### There wont be any server end) will receive the encrypted email, decrypt it. Is this correct? We will create our email application, therefore it will no longer be a black box. Correct?

### We will create a UI to send/receive emails in a secure way. We wont be creating any smtp servers or anything. So at the moment not all email services may be secure. The links below will help you understand I think. Our app is gonna make sure the data doesnt leak even if any email server/service does not support tls.
https://blog.google/products/gmail/making-email-safer-for-you-posted-by/
https://www.datamotion.com/2016/08/gmail-tls-email-encryption-good-enough/

2. "This way, the email provider (gmail/yahoo/etc) wont traverse the email as plaintext but ciphertext through their servers prevent data leakage (confidentiality)." I didnt quite understand the gmail/yahoo as email provider part. Gmail or Yahoo email providers do encrypt the messages before sending it on the transmission medium. 
### yes on the transmission medium, but if the servers dont agree with each other with the tls configuration, the conversation may revert back to plaintext
 
3. My task is to develop crypto technique to encrypt and decrypt the subject and the body right?
### yes


## IDEA OF THE PROJECT:
1. Create a Enc-Dec system to encrypt your messages first before sending it. This way even if one party does not have TLS Encryption enabled, the message will still be encrypted using our system as opposed to transmitting just plaintext.

2. The Enc-Dec system should be secure in case of data-modification attack, eavesdropping attack, and relay attack at the least.

3. Attack model: The sender has gmail (TLS Encryption) but receiver might not have TLS encrypted. So when some private and senstive information is to be sent from sender to the receiver, it will be transmited as plaintext. Hence, we build this new Encryption-Decryption model to thwart this attack.



## Industry apps to encrypt your email before sending it to the Google servers (if using gmail)
https://www.computerworld.com/article/2473585/encryption/easily-encrypt-gmail.html

1. Encrypted Communication: It uses AES-256

2. Encipher.it: It uses AES-256

3. Enlocked: It uses PGP encryption model https://www.enlocked.com/downloads/pr/enlocked-how-it-works-overview.pdf 

PGP can be used to send messages confidentially. For this, PGP combines symmetric-key encryption and public-key encryption. The message is encrypted using a symmetric encryption algorithm, which requires a symmetric key. Each symmetric key is used only once and is also called a session key. The message and its session key are sent to the receiver. The session key must be sent to the receiver so they know how to decrypt the message, but to protect it during transmission it is encrypted with the receiver's public key. Only the private key belonging to the receiver can decrypt the session key.

### PGP Encryption technique looks interesting and implements all that we learnt in course. I will try to implement this but take a look at Enlocked software. 

https://github.com/nimishalimaye/nscrypto-cpp uses hybrid encryption scheme, wherein public-key encryption like Diffie Hellman is used for key generation and symmetri-keyc encryption like AES is used for data encapsulation. This could be a good starting point for the project.

Other resources to look at when developing a secure cryptography algorithm: https://en.wikipedia.org/wiki/Pretty_Good_Privacy
https://en.wikipedia.org/wiki/Hybrid_cryptosystem 


## Working of SecureEmail python code.
1. The SecureEmail() function takes three arguments, option- generate RSA keys, Encrypt or decrypt; encrypt_flag: is encryption done before decrypting; and message(either plaintext or ciphertext)

<see end of file for instances>
 
 2. The generate public_private_key() function stores the generated keys in files on system. First send out the public keys then start the encryption process.
 

