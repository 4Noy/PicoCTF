import socket

hostname = "jupiter.challenges.picoctf.org"
port = 29956

def hex_2_char_l(c):
    if c < 'a':
        return ord(c) - ord('0')
    else:
        return 10 + ord(c) - ord('a')

def solve_bin(data):
    i = 0
    # Get to the start of the binary number
    while(data[i] not in "01"):
        i+=1

    result = ""
    while(data[i] in "01"):
        # Convert to a character
        result += chr(int(data[i:i+8], 2))
        i+=9 # 8 + the space
    return result

def solve_8_base(data):
    i = 0
    # Get to the start of the number
    while(data[i] not in "01234567"):
        i+=1

    result = ""
    while(data[i] in "01234567"):
        # Convert to a character
        result += chr(int(data[i:i+3], 8))
        i+=4 # 3 + the space
    return result

def solve_hexa(data):
    i = 0
    # Get to the start of the number
    while(data[i] not in "0123456789"):
        i+=1
    
    result = ""
    while(data[i] in "0123456789"):
        # Convert to a character 
        result += chr(hex_2_char_l(data[i]) * 16 + hex_2_char_l(data[i+1]))
        i+=2
    return result

def netcat(hostname, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, port))

    data = sock.recv(1024).decode()
    print("Received 1 :", data)
    
    # Convert from binary to a word
    result = solve_bin(data)

    sock.sendall((result + "\n").encode())
    print("Sent 1 :", result)


    # Then 8 base to word
    data = sock.recv(1024).decode()
    print("Received 2 :", data)
    
    result = solve_8_base(data)
    sock.sendall((result + "\n").encode())
    print("Sent 2:", result)

    
    # Hexa to dec
    data = sock.recv(1024).decode()
    print("Received 3 :", data)

    result = solve_hexa(data)
    sock.sendall((result + "\n").encode())
    print("Sent 3:", result)

    
    # Get the FLAAAAG
    data = sock.recv(1024).decode()
    print("Received 4 :", data)


netcat(hostname, port)
