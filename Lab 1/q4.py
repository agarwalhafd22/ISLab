import numpy as np

key=[[3,3],[2,7]]
msg = 'We live in an insecure world'
msg=msg.lower()
msgArr = msg.split(" ")
plainText=''
for x in msgArr:
    plainText+=x;

if len(plainText) % 2 != 0:
    plainText+='x'

i=1
cipherText=""
matrix = np.empty((2, 1))
n=len(plainText)
while i < n:
    matrix[0][0] = ord(plainText[i-1])-ord('a')
    matrix[1][0] = ord(plainText[i])-ord('a')
    result = np.dot(key,matrix)
    char1 = chr(((int)(result[0][0])%26)+ord('a'))
    char2 = chr(((int)(result[1][0])%26)+ord('a'))
    cipherText+=char1+char2
    i+=2

print("Plain Text:  ", plainText)
print("Cipher Text: ", cipherText)
