def additive_cipher_decryption(message, key):
    addDecipher = ""
    for char in message:
        if char == " ":
            addDecipher += char
        else:
            val=ord(char)-ord('a')-key
            if val < 0:
                addDecipher += chr(((val+26)%26)+ord('a'))
            else:
                addDecipher += chr((val%26)+ord('a'))
    return addDecipher

cipher_text = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"
for i in range(26):
    print(additive_cipher_decryption(cipher_text, i))
# key is 5 and plaintext = "cryptographxandsteganographyaretwosidesodacoqn"

