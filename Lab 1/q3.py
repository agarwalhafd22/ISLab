import string
alphabets = list(string.ascii_lowercase)
alphabets.remove('j')

#func to find pos of char
def find_element(matrix, target):
    for i in range(len(matrix)):
        for j in range(len(matrix[i])):
            if matrix[i][j] == target:
                return (i, j)
    return None

#removing spaces, converting to lowercase
msg = 'The key is hidden under the door pad'
msg=msg.lower()
msgArr = msg.split(" ")
plainText=''
for x in msgArr:
    plainText+=x;

#making the 5x5 matrix
key='guidance'
matrix = [['a' for _ in range(5)] for _ in range(5)]
keyIndex=0;
for i in range(5):  
    for j in range(5): 
        if(keyIndex<len(key)):
            alphabets.remove(key[keyIndex])
            matrix[i][j] = key[keyIndex]
            keyIndex+=1

        else:
            matrix[i][j] = alphabets.pop(0)

#converting plaintext to groups of two, adding bogus chars
plainTextList = list(plainText)
i = 0
while i < len(plainTextList) - 1:
    if plainTextList[i] == plainTextList[i + 1]:
        plainTextList.insert(i + 1, 'x')            
        i += 2
    else:
        i += 1
    
plainText = ''.join(plainTextList)
if len(plainText) % 2 != 0:
    plainText+='x'

#encyption
i=1
cipherText=""
n=len(plainText)
while i < n:
    char1 = plainText[i-1];
    char2 = plainText[i];
    pos1 = find_element(matrix,char1);
    pos2 = find_element(matrix,char2);
    if(pos1[0]==pos2[0]):
        char1 = matrix[pos1[0]][(pos1[1]+1)%5]
        char2 = matrix[pos1[0]][(pos2[1]+1)%5]
    elif(pos1[1]==pos2[1]):
        char1 = matrix[(pos1[0]+1)%5][pos1[1]]
        char2 = matrix[(pos2[0]+1)%5][pos1[1]]
    else:
        char1 = matrix[pos1[0]][pos2[1]]
        char2 = matrix[pos2[0]][pos1[1]]
    cipherText+=char1+char2
    i+=2
print("Plain Text:  ", plainText)
print("Cipher Text: ", cipherText)
