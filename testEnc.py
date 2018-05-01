from SecureEmail import SecureEmail_func

message = 'asjdabsjhdbvajsbj'
msb = message.encode('utf-8')

enc, cip = SecureEmail_func(1, False, msb)
print(type(cip))
print (cip)
dec = SecureEmail_func(2, True, cip)

print (str(dec))