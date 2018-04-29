from SecureEmail import SecureEmail

message = 'asjdabsjhdbvajsbj'

enc, cip = SecureEmail(1, message)
print (cip)