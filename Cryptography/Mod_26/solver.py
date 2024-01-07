def rot13(s):
    result = ""
    for v in s:
        c = ord(v)
        
        if c >= ord('a') and c <= ord('z'):
            if c > ord('m'):
                c -= 13
            else:
                c += 13

        elif c >= ord('A') and c <= ord('Z'):
            if c > ord('M'):
                c -= 13
            else:
                c += 13

        result += chr(c)

    return result
# The encrypted flag is in the "flag.enc.txt" file
with open('flag.enc.txt', 'r') as f:
    flag_enc = f.read()
flag = rot13(flag_enc)
print("The flag is :", flag)

