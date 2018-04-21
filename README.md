# SecureMail
WebUI to encrypt/decrypt and send/receive emails


# Initial thoughts

So What I have in mind is one WebUI where a user can input the email address/addresses, mail subject and body of the email. Send the email. Our program will encrypt the mail and send it using user's email ID (which he will provide during configuration of the application) to the email/emails that he provided in the webUI.

Another WebUI which will get the email from the user's email account and decrypt the encrypted email and display the content.(I need to figure out the details of this step) 

This way, the email provider (gmail/yahoo/etc) wont traverse the email as plaintext but ciphertext through their servers prevent data leakage (confidentiality). 
## nimisha
You can work on this ^ if you like - what are the cryptic advantages this method provides? how is this helpful?

Another thing that I would like you to work on is what kind of crypto should we use in this, since I have not been paying as much attention in the class, you would have a better idea on this. So we need to encrypt email subject and body, decrypt it on another host.
