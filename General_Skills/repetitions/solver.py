import base64

with open("enc_flag", "r") as f:
    strings = f.read().replace("\n", "")

def solve_b64(string):
    while True:
        try:
            string = (base64.b64decode(string.encode('ascii'))).decode('ascii')
            if "picoCTF" in string:
                print("Found the flag:", string)
                return
        except:
            break;
    return;

solve_b64(strings)

