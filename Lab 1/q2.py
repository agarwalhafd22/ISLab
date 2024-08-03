print("Enter a text:")
plainText=input()
n=len(plainText)
plainTextAS=""
print("\nPlain text: "+plainText)


for i in range (n):
	if plainText[i]!=" ":
		plainTextAS=plainTextAS+plainText[i]
		
n2=len(plainTextAS)

#Vigenère Cipher

key="dollars"
keyNew=""
c=0
i=0
while i<n2:
	if c==7:
		c=0
	keyNew=keyNew+key[c]
	c=c+1
	i=i+1

cipherVigenere=""
decryptedVigenere=""

for i in range (n2):
	cipherVigenere=cipherVigenere+chr((((ord(plainTextAS[i])+ord(keyNew[i])-97)%26)+97))
print("\nVigenere Cipher Text = "+cipherVigenere)

for i in range (n2):
	decryptedVigenere=decryptedVigenere+chr((((ord(cipherVigenere[i])-ord(keyNew[i])-97)%26)+97))
print("Vigenere Decrypted Text = "+decryptedVigenere)
