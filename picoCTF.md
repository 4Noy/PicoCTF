# picoCTF

---



## General Skills

---

### PW Crack 1

Here is the challenge :

```bash
PW_Crack_1
├── level1.flag.txt.enc
└── level1.py
```

The file `level1.flag.txt.enc` is just the encrypted flag.

But the `level1.py` contain this code :

**level1.py**

```python
# ...

flag_enc = open('level1.flag.txt.enc', 'rb').read()

def level_1_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    if( user_pw == "691d"):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")



level_1_pw_check()
```

So this program just call level_1_pw_check and then wait for a user input. If the user input is `"691d"` then is print the dectypted flag.

So we just have to write `691d` as a password and then we got the flag!

---

### PW Crack 2

Here is the challenge :

```bash
PW_Crack_2
├── level2.flag.txt.enc
└── level2.py
```

The file `level2.flag.txt.enc` is just the encrypted flag.

But the `level2.py` contain this code :

**level2.py**

```python
# ...

flag_enc = open('level2.flag.txt.enc', 'rb').read()

def level_2_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    if( user_pw == chr(0x33) + chr(0x39) + chr(0x63) + chr(0x65) ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")

level_2_pw_check()
```

So this program just call level_2_pw_check and then wait for a user input.

Then the program verify if the input is `chr(0x33) + chr(0x39) + chr(0x63) + chr(0x65)`

Than correspond to `39ce`, so we got the password to get the flag!

---

### PW Crack 3

Here is the challenge :

```bash
PW_Crack_3
├── level3.flag.txt.enc
├── level3.hash.bin
└── level3.py
```

So we got 2 files that contain some binary strings (`level3.flag.txt.enc` and `level3.hash.bin`) that are not useful for the moment.

Then we got `level3.py` that contain nice code:

**level3.py**

```python
# ...

flag_enc = open('level3.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level3.hash.bin', 'rb').read()

def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()

def level_3_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)

    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")

level_3_pw_check()

# The strings below are 7 possibilities for the correct password.
#   (Only 1 is correct)
pos_pw_list = ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]
```

So we got `hash_py` function that is supposed to return the hashed + bin of a string. And we got `level_3_pw_check` that is like the other **PW Crack X** just verifying if the string correspond to the password and then print the flag.

There is also the list `pos_pw_list` that contain 7 possible passwords and the right one. So we just have to try to encode each password in this list and then look if it correspond to the password in `level3.hash.bin`.

We just have to add few lines of code :

```python
for password in pos_pw_list:
    if(hash_pw(password) == correct_pw_hash):
        print("The password is :", password)
```

And we after executing the script, we got the password!

Note that we also can try all the password here and get the right one.

---

### PW Crack 4

Here is the challenge :

```bash
PW_Crack_4
├── level4.flag.txt.enc
├── level4.hash.bin
└── level4.py
```

So we got 2 files that contain some binary strings (`level4.flag.txt.enc` and `level4.hash.bin`) that are not useful for the moment.

But we got `level4.py` that contain this code:

```python
# ...

flag_enc = open('level4.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level4.hash.bin', 'rb').read()


def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()


def level_4_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)

    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")



level_4_pw_check()



# The strings below are 100 possibilities for the correct password.
#   (Only 1 is correct)
pos_pw_list = ["6288", "6152", "4c7a", "b722", "9a6e", "6717", "4389", "1a28", "37ac", "de4f", "eb28", "351b", "3d58", "948b", "231b", "973a", "a087", "384a", "6d3c", "9065", "725c", "fd60", "4d4f", "6a60", "7213", "93e6", "8c54", "537d", "a1da", "c718", "9de8", "ebe3", "f1c5", "a0bf", "ccab", "4938", "8f97", "3327", "8029", "41f2", "a04f", "c7f9", "b453", "90a5", "25dc", "26b0", "cb42", "de89", "2451", "1dd3", "7f2c", "8919", "f3a9", "b88f", "eaa8", "776a", "6236", "98f5", "492b", "507d", "18e8", "cfb5", "76fd", "6017", "30de", "bbae", "354e", "4013", "3153", "e9cc", "cba9", "25ea", "c06c", "a166", "faf1", "2264", "2179", "cf30", "4b47", "3446", "b213", "88a3", "6253", "db88", "c38c", "a48c", "3e4f", "7208", "9dcb", "fc77", "e2cf", "8552", "f6f8", "7079", "42ef", "391e", "8a6d", "2154", "d964", "49ec"]
```

So we got `hash_py` function that is supposed to return the hashed + bin of a string. And we got `level_4_pw_check` that is like the other **PW Crack X** just verifying if the string correspond to the password and then print the flag.

But we got `pos_pw_list` that contain all 100 possible passwords and only one is correct. 

So let's write some code after this code:

```python
for password in pos_pw_list:
    if(hash_pw(password) == correct_pw_hash):
        print("The password is :", password)
```

And after running the script we got the password and the flag!

---

### PW Crack 5

Here is the challenge:

```bash
PW_Crack_5
├── dictionary.txt
├── level5.flag.txt.enc
├── level5.hash.bin
└── level5.py
```

So we got 2 files that contain some binary strings (`level5.flag.txt.enc` and `level5.hash.bin`) that are not useful for the moment.

But we got `dictionary.txt` that contain a lot of words with a `\n` between each. Each word is a possible password as said in the challenge description.

And then we got `level5.py` that contain this code:

```python
# ...

flag_enc = open('level5.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level5.hash.bin', 'rb').read()


def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()


def level_5_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    user_pw_hash = hash_pw(user_pw)

    if( user_pw_hash == correct_pw_hash ):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), user_pw)
        print(decryption)
        return
    print("That password is incorrect")



level_5_pw_check()
```

So we got `hash_py` function that is supposed to return the hashed + bin of a string. And we got `level_5_pw_check` that is like the other **PW Crack X** just verifying if the string correspond to the password and then print the flag.

So the most simple way to solve this challenge is to add some code that open the file `dictionary.txt`, get all the possible passwords and then for each password if the is the right one.

The added code:

```python
with open("dictionary.txt", 'r') as file:
    passwords = file.read().split()

for password in passwords:
    if(hash_pw(password) == correct_pw_hash):
        print("The password is :", password)
```

And then we can find the password :)

---

### runme.py

There is only the file `runme.py` that literaly contain the flag, I don't know what the challenge was supposed to be.

---

### Serpentine

In this challenge there is just a file `serpentine.py`.

There is also a `print_flag` function, to solve this challenge, just call this function and the flag will be printed.

---

### First Find

First, we have to download the zip and unzip it.

We got this architecture:

```bash
files
├── 13771.txt.utf-8
├── 14789.txt.utf-8
├── acceptable_books
│   ├── 17879.txt.utf-8
│   ├── 17880.txt.utf-8
│   └── more_books
│       └── 40723.txt.utf-8
├── adequate_books
│   ├── 44578.txt.utf-8
│   ├── 46804-0.txt
│   └── more_books
│       └── 1023.txt.utf-8
└── satisfactory_books
    ├── 16021.txt.utf-8
    ├── 23765.txt.utf-8
    └── more_books
        └── 37121.txt.utf-8
```

The goal of this challenge is to find a file named `uber-secret.txt` we just have write a little command with `find` to get the path of the file and then look at what's inside.

---

### Big Zip

In this challenge we have a lot of file and directory with shitty text inside. So can search for a text inside a file, for example, all the flags start with `picoCTF` so searching for this string inside all the files is the right solution. With a little command that I found on [geeksforgeeks.org](https://geeksforgeeks.org) that combine `find` and `grep` command.

The command:

```shell
find -type f -exec grep -lr "picoCTF*" {} \;
```

And then we get the directory of the file containing this string and after displaying the content of the file we get the flag!

---

### chrono

For this challenge we have to connect to the server using ssh. The challenge talk about automate tasks to run on intervals on linux, I didn't knew what this challenge was about so as everyone else, I search how to automate tasks on linux. And the first website talked about **Crontab** and a file `/etc/crontab` so I looked inside this file and found the flag!

---

### money-ware

The challenge give a bitcoin address and we have to find the name of the malware that own the bitcoin address, we can got this by searching the bitcoin address on any search engine.

---

### Permissions

In this challenge we have to connect through ssh to the server. The goal of this challenge is to read files in root directory. I didn't knew how to look at my permissions so I searched on the internet and found `sudo -l` command that contains what I'm allow to use. And I saw that there was a command that I can use as a root `/usr/bin/vi` which is a text editor that also can execute commands, so I openned `vi` and tried to open a shell with `:!/bin/bash`. 

After this we have a shell as root user and we can find the hidden file in `/root` directory to get the flag.

---

### repetitions

This challenge is all about base64, we get a file that contain few lines with base64 encoded strings, so I tried to decode them, but that didn't turn nice, as the hint suggest, *Multiple decoding is always good.* so maybe the base64 encoded strings can be decode multiple times.

So I wrote a script that took every lines and try to decode th/em. But that didn't work because these base64 encoded strings can be seen as a whole base64 encode strings, so after modifying my script I got this :

```python
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
```

And then I could get the flag!

---

### ASCII Numbers

In this challenge, ascii string is given:

```python
0x70 0x69 0x63 0x6f 0x43 0x54 0x46 0x7b 0x34 0x35 0x63 0x31 0x31 0x5f 0x6e 0x30 0x5f 0x71 0x75 0x33 0x35 0x37 0x31 0x30 0x6e 0x35 0x5f 0x31 0x6c 0x6c 0x5f 0x74 0x33 0x31 0x31 0x5f 0x79 0x33 0x5f 0x6e 0x30 0x5f 0x6c 0x31 0x33 0x35 0x5f 0x34 0x34 0x35 0x64 0x34 0x31 0x38 0x30 0x7d
```

We have to convert it to a readable string.

So let's write a little algorithm that convert these into the corresponding string.

The algorithm is going to go through each hexa values (the `0xAB`) and get the `A` and the `B` to get the corresponding character. 

```python
def character_hex_2_dec_lowercase(c):
    if c < 'a':
        return ord(c) - ord('0')
    else:
        return 10 + ord(c) - ord('a')

with open("string.txt", "r") as f:
    string = f.read() # Read the content of the file

res = ""
for i in range(0, len(string), 5):
    # Get the two values composing the character
    first_character = character_hex_2_dec_lowercase(string[i+2])
    second_character = character_hex_2_dec_lowercase(string[i+3])

    # Get the character
    character = chr(first_character * 16 + second_character)
    res += character

print(res)
```

And with this type of script we can get the flag!

---

### Based

So in this challenge, we have to connect to the server and answer the question. The questions are all about bases, converting numbers to words.

I decided to write a script, in python, that is gonna guess the answer to the question.

First we need to **connect to the server**:

For this I'm gonna use a simple python script that use socket.

```python
import socket

hostname = "hostname"
port = 00000

def netcat(hostname, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((hostname, port))

    # Receive Data
    data = sock.recv(1024).decode()
    print("Received:", data)

    # Do things ...

    # Send Data
    sock.sendall((result + "\n").encode()) # As it should end with "\n"
    print("Sent:", result)
```

With this script you can connect to the server, get data and send some

The **First** question is this one (the numbers may vary):

```
Let us see how data is stored
animation
Please give the 01100001 01101110 01101001 01101101 01100001 01110100 01101001 01101111 01101110 as a word.
...
you have 45 seconds.....

Input:
```

The word is literally in the text but let's have fun with python.

The script is just gonna find where the numbers are, convert each one and build the word.

An exemple of script:

```python
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
```

From the given string, it return the corresponding word.

The **Second** question (the numbers may vary):

```
Please give me the  146 141 154 143 157 156 as a word.
Input:
```

After few attempts we can see that there is no numbers that are over 7 => base 8

Now we can write a nice script that convert from this format to the corresponding word.

```python
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
```

Second question clear!

The **Third** question (the numbers may vary):

```
Please give me the 6d6170 as a word.
Input:
```

It's clear that this is a word in base 16. This give us the script that follow.

```python
def hex_2_char_l(c):
    if c < 'a':
        return ord(c) - ord('0')
    else:
        return 10 + ord(c) - ord('a')

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
```

Nice!

With all these pieces together the flag can be catched.

---

### plumbing

The first step in this challenge is to connect to the server, using `nc` this is very simple, but after connecting, you get a huge flow of data with a lot of unwanted stuff.

So first, let's get the content and put it in a file, to redirect the data, use `>`. The comment should look like this:

```bash
nc jupiter.challenges.picoctf.org 4427 > flag.txt
```

With this command, we get a lot of stuff inside the `flag.txt` file. 

Next step is to find the flag in this file for this, just use the `grep` command. For example, use this command:

```bash
grep -e picoCTF flag.txt
```

Then you get the flag!

---

### mus1c

For this challenge, you have a file called `lyrics.txt` that contain, at first sight, some lyrics.

**lyrics.txt**

```rockstar
Pico's a CTFFFFFFF
my mind is waitin
It's waitin

Put my mind of Pico into This
my flag is not found
put This into my flag
put my flag into Pico


shout Pico
shout Pico
shout Pico

My song's something
put Pico into This

Knock This down, down, down
put This into CTF

shout CTF
my lyric is nothing
Put This without my song into my lyric
Knock my lyric down, down, down

shout my lyric

Put my lyric into This
Put my song with This into my lyric
Knock my lyric down

shout my lyric

Build my lyric up, up ,up

shout my lyric
shout Pico
shout It

Pico CTF is fun
security is important
Fun is fun
Put security with fun into Pico CTF
Build Fun up
shout fun times Pico CTF
put fun times Pico CTF into my song

build it up

shout it
shout it

build it up, up
shout it
shout Pico
```

The hint talk about rockstar, which is (I didn't knew) a "coding language". Searching on the web I found [this](https://codewithrockstar.com/]) website that can translate rockstart code into numbers apparently...

I stored the numbers in this file, **rocked.txt**

```
114
114
114
111
99
107
110
114
110
48
49
49
51
114
```

With this we can get all the numbers that can be now be transformed in characters:

Little python code:

```python
with open("rocked.txt", "r") as f:
    values = f.readlines()

res = ""
for value in values:
    res += chr(int(value))
print(res)
```

We inject this into `picoCTF{}` to finish getting the flag.

---

### flag_shop

For this challenge, we got a file `store.c` that contain de source code of the script running on the remote server. To connect to the server and interact with it, just use `netcat` alias  `nc`.

The source code `store.c` wait print choices and wait for an input of the user to do the choosen action, it is organized like this :

```
1. Check Account Balance
└── Show Account Balance

2. Buy Flags
├── 1. Buy normal flags (Not the real one)
│   └── Enter the desired quantity (900 per flag)
└── 2. Get the real flag (Cost 100000)

3. Exit
└── Exit the program
```

So if you choose `2` first and `1` you have to write down the numer of flag you want to buy.

This whole program use the `int` variable `account_balance` to store our money.

So the goal of this challenge is to have `account_balance` > 100000 to get the real flag.

After a quick look on the source code, we figure that the only moment `account_balance` is modified the when you buy normal flags. So this is the part we have to focus on.

```c
if(auction_choice == 1){
    printf("These knockoff Flags cost 900 each, enter desired quantity\n");

    int number_flags = 0;
    fflush(stdin);
    scanf("%d", &number_flags); // Enter desired quantiy

    if(number_flags > 0){ // Check if it is > 0
        int total_cost = 0;
        total_cost = 900*number_flags; // Calculate the price

        printf("\nThe final cost is: %d\n", total_cost);

        if(total_cost <= account_balance){ // Check if you have enough money
            account_balance = account_balance - total_cost;
            printf("\nYour current balance after transaction: %d\n\n", account_balance);
        }
        else{
            printf("Not enough funds to complete purchase\n");
        }
    }
}
```

So in this part, the program is waiting for you to enter the desired quantity, it also gonna verify if this number is over 0, calculate the price of the flags, verify if you have enough money and then calculate the remaining money.

So to summarize, the only way to get more money is here:

```c
account_balance = account_balance - total_cost;
```

So if `- total_cost` > 0 we gain money. And for `total_cost`  < 0, `900*number_flags` need to be < 0. However  `number_flags` need to be > 0 enter the `if`.

We have to get this situation:

- `number_flag` > 0

- `total_cost` = `900*number_flags` < 0

To get this, are gonna play with the size of `int` type in `C`. In `C` programming language, `int` as a finite size, so if your number is too big, it gets negative.

#### <u>Explanation</u>:

Imagine that the `int` type as a size of 2 bytes, the number can be negative or positive, so the computer have to know the sign of the number, for that, it's gonna use the most significant bit.

|                          | Positive | Negative |
|:------------------------:|:--------:|:--------:|
| **Most significant bit** | 0        | 1        |

<u>**Example:**</u>

|                        | Positive            | Negative            |
| ---------------------- |:-------------------:|:-------------------:|
| **Decimal Value**      | 32278               | -2                  |
| **Bit Representation** | 0111 1110 0001 0110 | 1111 1111 1111 1110 |

So if we multiply **32278** by 2, we get this binary representation :

`32278 * 2 = 1111 1100 0010 1100 (in base 2)`  which is equal to **-980** as the most significant bit is 1 it gets negative!

#### Solving the challenge

So if we can get `number_flags` just enough big to be > 0 but multiplied by 900 it gets too big to fit in the `int` size, we can get negative numbers!

**The `int` size is actualy 32 bits here.**

Let's try with **1073741823** that is `0111 1111 1111 1111 1111 1111 1111 1111` in binary. Multiplied by 900 is **966367640700** that correspond to `1110 0000 1111 1111 1111 1111 1111 1100 0111 1100`, but the int size is **32 BITS**! So it is `1111 1111 1111 1111 1111 1100 0111 1100`, that **start with 1**, so it is **negative** and is equal to -900.

```
These knockoff Flags cost 900 each, enter desired quantity
1073741823

The final cost is: -900

Your current balance after transaction: 2000
```

We can now gain money!

And if we try with another numer using the same technique, **1073741500** for example.

```
These knockoff Flags cost 900 each, enter desired quantity
1073741500

The final cost is: -291600

Your current balance after transaction: 292700
```

Nice, we get the needed money!

Now let's go buy the real flag!

---

### 1_wanna_b3_a_r0ck5tar

In this challenge, we have given lyrics:

```rockstar
Rocknroll is right
Silence is wrong
A guitar is a six-string
Tommy's been down
Music is a billboard-burning razzmatazz!
Listen to the music
If the music is a guitar
Say "Keep on rocking!"
Listen to the rhythm
If the rhythm without Music is nothing
Tommy is rockin guitar
Shout Tommy!
Music is amazing sensation
Jamming is awesome presence
Scream Music!
Scream Jamming!
Tommy is playing rock
Scream Tommy!
They are dazzled audiences
Shout it!
Rock is electric heaven
Scream it!
Tommy is jukebox god
Say it!
Break it down
Shout "Bring on the rock!"
Else Whisper "That ain't it, Chief"
Break it down
```

These lyrics are in a coding language called Rockstar. After running this script on [codewithrockstar.com](https://web.archive.org/web/20190522020843/https://codewithrockstar.com/online), using web.archive.org because the language apparently changed, we find out that we have to enter inputs into a field and sending anything doesn't work. So we have to understand the Rockstar code a little.

After a quick view on the [Rockstar documentation](https://codewithrockstar.com/docs) we find out that lines with `... is ...` is like defining a variable, also that we can print some text using `Scream` or other equivalent keywords. The keywords `listen` is the one that waits for an input.

So the first step to understand how Rockstar works is to enter in the `If` condition following:

```rockstar
If the music is a guitar
Say "Keep on rocking!"
```

So `the music` is our input and it check if it is `a guitar`, to know what the `a guitar` is, just `Scream` it!

```rockstar
...
A guitar is a six-string
...
Scream a guitar
---------------
136
```

Nice, we now know what our first input is supposed to be!

Now there is a second `If` condition:

```rockstar
If the rhythm without Music is nothing
```

So, looking the documentation, `without` is minus and `nothing` is equivalent to NULL and 0.

We know that our second input as to be equal to `Music`. And as the first step, if you don't know `Scream` it!

```rockstar
...
Music is a billboard-burning razzmatazz!
...
Scream Music
---------------
1970
```

We got our second input!

The code can now be re-run, write the inputs, and you got this:

```
Keep on rocking!
66
79
78
74
79
86
73
```

If we take all our numbers here and convert them into a word, we can now submit our flag!

I've made a simple python script for this, just put the numbers in a file `rocked.txt` and then run the script:

```python
with open("rocked.txt", "r") as f:
    values = f.readlines()

res = ""
for value in values:
    res += chr(int(value))
print(res)
```

Inject it into **picoCTF{}** and you got it!

---

### useless

In this challenge we have to connect by ssh to the remote server, and there is just one interesting file `useless`, a shell script that can be executed. Let's see what's inside:

**useless**

```shell
#!/bin/bash
# Basic mathematical operations via command-line arguments

if [ $# != 3 ]
then
  echo "Read the code first"
else
    if [[ "$1" == "add" ]]
    then
      sum=$(( $2 + $3 ))
      echo "The Sum is: $sum"

    elif [[ "$1" == "sub" ]]
    then
      sub=$(( $2 - $3 ))
      echo "The Substract is: $sub"

    elif [[ "$1" == "div" ]]
    then
      div=$(( $2 / $3 ))
      echo "The quotient is: $div"

    elif [[ "$1" == "mul" ]]
    then
      mul=$(( $2 * $3 ))
      echo "The product is: $mul"

    else
      echo "Read the manual"

    fi
fi
```

It say "***Read the manual***", let's read it with `man`.

```bash
picoplayer@challenge:~$ man useless
useless
     useless, — This is a simple calculator script

SYNOPSIS
     useless, [add sub mul div] number1 number2

DESCRIPTION
     Use the useless, macro to make simple calulations like addi‐
     tion,subtraction, multiplication and division.

Examples
     ./useless add 1 2
       This will add 1 and 2 and return 3

     ./useless mul 2 3
       This will return 6 as a product of 2 and 3

     ./useless div 6 3
       This will return 2 as a quotient of 6 and 3

     ./useless sub 6 5
       This will return 1 as a remainder of substraction of 5 from 6

Authors
     This script was designed and developed by Cylab Africa

     The flag :)
```

We got the flag!

---

### Special

In this challenge we have to connect by ssh to the remote server, the shell looks very strange and when you try to use commands it change the command into words (to avoid spelling mistakes), even if it can be very usefull, it is not good for use since we have to use commands to do things.

For example, using `ls` give this:

```bash
Special$ ls
Is
sh: 1: Is: not found
```

First thing is to find how we can use commands, let's try with an absolute path:

```bash
Special$ /bin/ls
Absolutely not paths like that, please!
```

It doesn't work, so let's try with a relative path:

```shell
Special$ ../../bin/ls
../../bin/ls
blargh
```

Nice, we can use commands and there is a directory called `blargh` here, let's see what's inside. And since `blargh` is not a real word, don't forget to use a relative path.

```shell
Special$ ../../bin/ls ./blargh
../../bin/ls ./blargh
flag.txt
```

We now got the file `flag.txt`, let's use `cat` to look at the content of the file.

```shell
Special$ ../../bin/cat ./blargh/flag.txt
../../bin/cat ./blargh/flag.txt
The Flag :)
```

We now got the flag!

---

### Specialer

The is the next challenge after **Special**, first, you have to connect by ssh to the remote server. 

There is a strange shell that cannot execute a lot of commands.

```shell
Specialer$ ls
-bash: ls: command not found
```

But some still work:

```shell
Specialer$ echo "Hello"
Hello
Specialer$ pwd
/home/ctf-player
```

Since `echo` is working, we now can display the files and directories using `echo *`:

```shell
Specialer$ echo *
abra ala sim
```

Now let's look at the files inside these directories:

```shell
Specialer$ echo abra/*
abra/cadabra.txt abra/cadaniel.txt
Specialer$ echo ala/*
ala/kazam.txt ala/mode.txt
Specialer$ echo sim/*
sim/city.txt sim/salabim.txt
```

Now we hope that the flag is here, because after looking around, there is no other interesting files on this remote server.

To look inside a file using `echo`, use `echo "$(<file.txt)"` (I found that on internet), the challenge can now be solved.

```shell
sim/city.txt sim/salabim.txt
Specialer$ echo "$(<abra/cadabra.txt)"
Nothing up my sleeve!
Specialer$ echo "$(<abra/cadaniel.txt)"
Yes, I did it! I really did it! I'm a true wizard!
Specialer$ echo "$(<ala/kazam.txt)"
return 0 The Flag :)
```

Nice, challenge finished!

---

 

## Reverse Engineering

Looks Nice!

---

In this challenge we only got one file `keygenme-trial.py` which is a little application that calculate things that we don't need to know about because the interesting part in this script is how to **activate the license**.

The variables used to verify the license are these:

```python
username_trial = "GOUGH"
bUsername_trial = b"GOUGH"

key_part_static1_trial = "picoCTF{1n_7h3_|<3y_of_"
key_part_dynamic1_trial = "xxxxxxxx"
key_part_static2_trial = "}"
key_full_template_trial = key_part_static1_trial + key_part_dynamic1_trial + key_part_static2_trial
```

Here, we can see that there is the beginning of the flag but there is a **part with 'x' that we are gonna try to find**.

When you try to activate a licence, it first call this function `enter_license`.

```python
def enter_license():
    user_key = input("\nEnter your license key: ")
    user_key = user_key.strip()

    global bUsername_trial

    if check_key(user_key, bUsername_trial):
        decrypt_full_version(user_key)
    else:
        print("\nKey is NOT VALID. Check your data entry.\n\n")
```

So this wait for an input of the user, `strip` it and now call `check_key`.

```python
def check_key(key, username_trial):
    global key_full_template_trial

    if len(key) != len(key_full_template_trial):
        return False
    else:
        # Verify if the start of our input is "picoCTF{1n_7h3_|<3y_of_"
        i = 0
        for c in key_part_static1_trial:
            if key[i] != c:
                return False
            i += 1

        # ... (Some other code that I'm gonna explain later)         

        return True
```

With this function, we first notice that our input (`key`) need to have a size equal to the size of `key_full_template_trial` which is the flag but with unknown part (the `key_part_dynamic1_trial`, all the 'x').

Then the rest of the code here is verify if the start of our input is the string `key_part_static1_trial` which is "picoCTF{1n_7h3_|<3y_of_".

The rest of this function is gonna help us find what the rest of our input needs to be.

```python
  def check_key(key, username_trial):

        # ...

        if key[i] != hashlib.sha256(username_trial).hexdigest()[4]:
            return False
        else:
            i += 1
        if key[i] != hashlib.sha256(username_trial).hexdigest()[5]:
            return False
        else:
            i += 1
        if key[i] != hashlib.sha256(username_trial).hexdigest()[3]:
            return False
        else:
            i += 1
        if key[i] != hashlib.sha256(username_trial).hexdigest()[6]:
            return False
        else:
            i += 1
        if key[i] != hashlib.sha256(username_trial).hexdigest()[2]:
            return False
        else:
            i += 1
        if key[i] != hashlib.sha256(username_trial).hexdigest()[7]:
            return False
        else:
            i += 1
        if key[i] != hashlib.sha256(username_trial).hexdigest()[1]:
            return False
        else:
            i += 1
        if key[i] != hashlib.sha256(username_trial).hexdigest()[8]:
            return False

        return True
```

We know that the `i` variable is now equal to the lenght of `key_part_static1_trial` which is the rest of our string after "picoCTF{1n_7h3_|<3y_of_".

So this part check things on the section of the flag that contain 'x'.

Each `if` statement is similar to the other one, it verify if the next character is equal to one precise character of the sha256 of `username_trial` which is `bUsername_trial` (the binary string "GOUGH").

First, we need to know the value of `hashlib.sha256(username_trial).hexdigest()`, fo this, just print it when the program call `check_key`.

We now know the value of it : `e8a1f9146d32473b9605568ca66f7b5c2db9f271f57a8c8e9e121e48accddf2f`.

The first value of the rest of the flag can be found here:

```python
if key[i] != hashlib.sha256(username_trial).hexdigest()[4]:
    return False
else:
    i += 1
```

It is the 5 value (don't forget that it starts from 0) of the hashed string we got earlier, so it is a 'f'.

We can continue this process for the rest of the function and get the flag!

---

### crackme-py

This challenge  contain a useless program that choose the greatest value between two, but there is also en encoded string (`bezos_cc_secret`) and a decode function (`decode_secret`). If we call the decode function with the encoded string we can get the flag.

---

### file-run1

In this challenge we got one file `run`. After downloading this file we have to give us the permission to run it using `chmod`:

```shell
chmod +x run
```

And then we can run the script to optain the flag.

---

### file-run2

For this challenge we got one file `run`.After downloading this file we have to give us the permission to run it using `chmod`:

```shell
chmod +x run
```

And then we can run the script and get the following result:

```shell
$ ./run
Run this file with only one argument.
```

This give us the information that we have to run the script with one argument. Let's try:

```shell
$ ./run abc
Won't you say 'Hello!' to me first?
```

I guess we have to run the script with the argument `Hello!`:

```shell
$ ./run Hello!
The flag is: The flag :)
```

We got the flag!

--- 

### patchme.py

For this challenge we get an encrypted flag and a python program that contain a function called `level_1_pw_check` that we are gonna analyse.

```python
# ...

def level_1_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    if( user_pw == "ak98" + \
                   "-=90" + \
                   "adfjhgj321" + \
                   "sleuth9000"):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), "utilitarian")
        print(decryption)
        return
    print("That password is incorrect")

level_1_pw_check()
```

This function is waiting for an input and then verify if it match with the wanted password.

Our input must be the same as :

```python
"ak98" + \
"-=90" + \
"adfjhgj321" + \
"sleuth9000"
```

This is just a concatenation of these strings, so the input must be `ak98-=90adfjhgj321sleuth9000`.

Let's try it:

```bash
$ py patchme.flag.py
Please enter correct password for flag: ak98-=90adfjhgj321sleuth9000
Welcome back... your flag, user:
The flag :)
```

We got it!

---

### Safe Opener

For this challenge, one file is given and we need to analyse it:

**SafeOpener.java**

```java
import java.io.*;
import java.util.*;
public class SafeOpener {
    public static void main(String args[]) throws IOException {
        BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
        Base64.Encoder encoder = Base64.getEncoder();
        String encodedkey = "";
        String key = "";
        int i = 0;
        boolean isOpen;


        while (i < 3) {
            System.out.print("Enter password for the safe: ");
            key = keyboard.readLine();

            encodedkey = encoder.encodeToString(key.getBytes());
            System.out.println(encodedkey);

            isOpen = openSafe(encodedkey);
            if (!isOpen) {
                System.out.println("You have  " + (2 - i) + " attempt(s) left");
                i++;
                continue;
            }
            break;
        }
    }

    public static boolean openSafe(String password) {
        String encodedkey = "cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz";

        if (password.equals(encodedkey)) {
            System.out.println("Sesame open");
            return true;
        }
        else {
            System.out.println("Password is incorrect\n");
            return false;
        }
    }
}
```

We have to analyse the first lines of the code after the main method:

```java
BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
Base64.Encoder encoder = Base64.getEncoder();
String encodedkey = "";
String key = "";
int i = 0;
boolean isOpen;
```

We can find that `encoder` is a base 64 encoder.

Now let's analyse the rest of the method:

```java
while (i < 3) {
    System.out.print("Enter password for the safe: ");
    key = keyboard.readLine();

    encodedkey = encoder.encodeToString(key.getBytes());
    System.out.println(encodedkey);

    isOpen = openSafe(encodedkey);
    if (!isOpen) {
        System.out.println("You have  " + (2 - i) + " attempt(s) left");
        i++;
        continue;
    }
    break;
}
```

The part of the code wait for an input, encode it with base 64 (`encoder` is a base 64 encoder), and then call the `openSafe` function with the encoded input and return `true` if it open and `false` if it don't. The next step is to analyse the `openSafe` function.

```java
public static boolean openSafe(String password) {
    String encodedkey = "cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz";

    if (password.equals(encodedkey)) {
        System.out.println("Sesame open");
        return true;
    }
    else {
        System.out.println("Password is incorrect\n");
        return false;
    }
}
```

This function has a string called `encodedkey` and is gonna verify if the string `password` given in argument is equal to `encodedkey`.

We have to do some Reverse Engineering with the code.

The `main` method take our input and encode it with base 64 and then the  `openSafe` function verify if the encoded input is equal to `encodedkey`. To make them match we have to decode `encodedkey` and put it as the input.

The decoded version of `encodedkey` is : `"pl3as3_l3t_m3_1nt0_th3_saf3"`.

We now got the password!

---

### unpackme.py

For this challenge we get one file `unpackme.flag.py` that contain this code:

**unpackme.flag.py**

```python
import base64
from cryptography.fernet import Fernet



payload = b'gAAAAABkzWGSzE6VQNTzvRXOXekQeW4CY6NiRkzeImo9LuYBHAYw_hagTJLJL0c-kmNsjY33IUbU2IWlqxA3Fpp9S7RxNkiwMDZgLmRlI9-lGAEW-_i72RSDvylNR3QkpJW2JxubjLUC5VwoVgH62wxDuYu1rRD5KadwTADdABqsx2MkY6fKNTMCYY09Se6yjtRBftfTJUL-LKz2bwgXNd6O-WpbfXEMvCv3gNQ7sW4pgUnb-gDVZvrLNrug_1YFaIe3yKr0Awo0HIN3XMdZYpSE1c9P4G0sMQ=='

key_str = 'correctstaplecorrectstaplecorrec'
key_base64 = base64.b64encode(key_str.encode())
f = Fernet(key_base64)
plain = f.decrypt(payload)
exec(plain.decode())
```

We got a payload, and a few lines that do different things and then we got the `exec` function that execute python code. And when you try to run the script it wait for an input, meaning that the `plain` variable contain python code as a string. We can print it to see what's inside and we can see the python code and the flag!

---

### ARMassembly 0

I achieved this challenge by following [this](https://mariokartwii.com/armv8/) tutorial and understanding the main part of the program and then convert the given numbers into hex and got the flag.

---

### Ready Gladiator 0

In this challenge we have to send a warrior to the server using `nc` and lose all our rounds.

The starting warior is this one:

**imp.red**

```
;redcode
;name Imp Ex
;assert 1
mov 0, 1
end
```

Just try to play with the mov values and you easily get the flag.

---

### Reverse

Before searching too deep, just try to look at the content of a file :).

---

### Safe Opener 2

Just use the grep or cat command!!!

---



## Cryptography

Math knowledge is nice for this section

---

### Mod 26

For this challenge we get this encrypted flag : ``cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_GYpXOHqX}`` and the challenge talk about ROT13, so let's write a little python algorithm that decrypt this flag!

```python
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
```

And we can now run the script and solve the challenge!

*More information about [ROT13](https://en.wikipedia.org/wiki/ROT13)*

---
