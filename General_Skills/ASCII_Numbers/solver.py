def character_hex_2_dec_lowercase(c):
    if c < 'a':
        return ord(c) - ord('0')
    else:
        return 10 + ord(c) - ord('a')

with open("string.txt", "r") as f:
    string = f.read()
res = ""
for i in range(0, len(string), 5):
    first_character = character_hex_2_dec_lowercase(string[i+2])
    second_character = character_hex_2_dec_lowercase(string[i+3])
    character = chr(first_character * 16 + second_character)
    res += character
print(res)
