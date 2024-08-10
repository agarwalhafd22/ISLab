print("Encrypted Text: CIW")

eText="ciw"
dText="yes"

key=((ord(eText[0])-97)-(ord(dText[0])-97))%26

print("Key = ",key)

print("Engraved Text: XVIEWYWI")

encryptedText="xviewywi"
decryptedText=""

n=len(encryptedText)

for i in range (n):
    decryptedText = decryptedText + chr((ord(encryptedText[i]) - 97 - key) % 26 + 97)

print("Decrypted Text = "+decryptedText)

