with open("rocked.txt", "r") as f:
    values = f.readlines()

res = ""
for value in values:
    res += chr(int(value))
print(res)
