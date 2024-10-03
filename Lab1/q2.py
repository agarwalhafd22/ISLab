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
	cipherVigenere=cipherVigenere+chr((((ord(plainTextAS[i])-97+ord(keyNew[i])-97)%26)+97))
print("\nVigenere Cipher Text = "+cipherVigenere)

for i in range (n2):
	decryptedVigenere=decryptedVigenere+chr((((ord(cipherVigenere[i])-97-(ord(keyNew[i])-97))%26)+97))
print("Vigenere Decrypted Text = "+decryptedVigenere)


#Autokey Cipher


autoKey=7
cipherAutoKey=""
cipherAutoKeyInter=""
cipherAutoKeyInter=cipherAutoKeyInter+chr(7+97)
for i in range (n2-1):
	cipherAutoKeyInter=cipherAutoKeyInter+plainTextAS[i]

for i in range (n2):
	cipherAutoKey=cipherAutoKey+chr(((ord(plainTextAS[i])-97+ord(cipherAutoKeyInter[i])-97)%26)+97)

print("\nAutokey Cipher Text = " + cipherAutoKey)

decryptedAutoKey=""
decryptedAutoKey=decryptedAutoKey+chr((ord(cipherAutoKey[0])-97-autoKey)+97)

for i in range (1, n2):
	decryptedAutoKey=decryptedAutoKey+chr(((ord(cipherAutoKey[i])-97-(ord(decryptedAutoKey[i-1])-97))%26)+97)

print("Autokey Decrypted Text = "+decryptedAutoKey)
