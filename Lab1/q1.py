print("Enter a text:")
plainText=input()
n=len(plainText)
plainTextAS=""
print("\nPlain text: "+plainText)


for i in range (n):
	if plainText[i]!=" ":
		plainTextAS=plainTextAS+plainText[i]
		
n2=len(plainTextAS)


#Additive Cipher

cipherAdditive=""
decryptedAdditive=""

for i in range (n2):
	if ord(plainTextAS[i])>=97:
		cipherAdditive=cipherAdditive+chr(((((ord(plainTextAS[i])-97)+20)%26)+97))
	else:
		cipherAdditive=cipherAdditive+chr(((((ord(plainTextAS[i])-65)+20)%26)+65))
print("\nAdditive Cipher Text: "+cipherAdditive)

for i in range (n2):
	if ord(cipherAdditive[i])>=97:
		if ord(cipherAdditive[i])-97-20<0:
			decryptedAdditive=decryptedAdditive+chr(26-(-1*(ord(cipherAdditive[i])-97-20)%26)+97)
		else:
			decryptedAdditive=decryptedAdditive+chr((ord(cipherAdditive[i])-97-20)%26+97)
	else:
		if ord(cipherAdditive[i])-65-20<0:
			decryptedAdditive=decryptedAdditive+chr(26-(-1*(ord(cipherAdditive[i])-65-20)%26)+65)
		else:
			decryptedAdditive=decryptedAdditive+chr((ord(cipherAdditive[i])-65-20)%26+65)
print("Additive Decrypted Text: "+decryptedAdditive)		


#Multiplicative Cipher

'''
#finding inverse

num = [1,3,5,7,9,11,15,17,19,21,23,25]
for i in range (12):
	if (15*num[i])%26==1:
		print(num[i])
		break
'''

cipherMultiplicative=""
decryptedMultiplicative=""

for i in range (n2):
	if ord(plainTextAS[i])>=97:
		cipherMultiplicative=cipherMultiplicative+chr(((((ord(plainTextAS[i])-97)*15)%26)+97))
	else:
		cipherMultiplicative=cipherMultiplicative+chr(((((ord(plainTextAS[i])-65)*15)%26)+65))
print("\nMultiplicative Cipher Text: "+cipherMultiplicative)



for i in range (n2):
	if ord(cipherMultiplicative[i])>=97:
		decryptedMultiplicative=decryptedMultiplicative+chr(((ord(cipherMultiplicative[i])-97)*7)%26+97)
	else:
		decryptedMultiplicative=decryptedMultiplicative+chr(((ord(cipherMultiplicative[i])-65)*7)%26+65)
print("Multiplicative Decrypted Text: "+decryptedMultiplicative)	



#Affine Cipher


cipherAffine=""
decryptedAffine=""

for i in range (n2):
	if ord(plainTextAS[i])>=97:
		cipherAffine=cipherAffine+chr((((((ord(plainTextAS[i])-97)*15)+20)%26)+97))
	else:
		cipherAffine=cipherAffine+chr((((((ord(plainTextAS[i])-65)*15)+20)%26)+65))
print("\nAffine Cipher Text: "+cipherAffine)



for i in range (n2):
	if ord(cipherAffine[i])>=97:
		decryptedAffine=decryptedAffine+chr((((ord(cipherAffine[i])-97)-20)*7)%26+97)
	else:
		decryptedAffine=decryptedAffine+chr((((ord(cipherAffine[i])-65)-20)*7)%26+65)
print("Affine Decrypted Text: "+decryptedAffine)
