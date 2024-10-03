'''
t1 = "ab"
t2 = "gl"
num = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]


def check(i, j):
    if (((ord(t2[1]) - 97) - j) * num[i]) % 26 == (ord(t1[1]) - 97) % 26:
        return True
    else:
        return False


c = 0

for i in range(12):
    for j in range(26):
        if (((ord(t2[0]) - 97) - j) * num[i]) % 26 == (ord(t1[0]) - 97) % 26:
            if check(i, j):
                c = 1
                break
    if c == 1:
        break

for k in range(12):
    if (num[i] * num[k]) % 26 == 1:
        break;

encryptedText = "xpalasxyfgfukpxusogeutkcdgexanmgnvs"
decryptedText = ""

n2 = len(encryptedText)

for i in range(n2):
    decryptedText = decryptedText + chr((((ord(encryptedText[i]) - 97) - j) * num[k]) % 26 + 97)

print("Decrypted Text: "+decryptedText)

'''


'''
def find_affine_parameters():
    for a in range(1, 26):  # a must be coprime with 26
        if gcd(a, 26) == 1:  # check if a is coprime with 26
            for b in range(26):
                # Check if the encryption formula satisfies the given condition
                if ((a * ord('a') + b) % 26 == ord('g') and
                        (a * ord('b') + b) % 26 == ord('l')):
                    return a, b

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

a, b = find_affine_parameters()
print(f"a = {a}, b = {b}")
'''
