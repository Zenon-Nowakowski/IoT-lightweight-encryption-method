import socket
from main import * 
hostname=socket.gethostname()   
IPAddr=socket.gethostbyname(hostname) 

s= socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

# my IP 
host = IPAddr   
#print to make sure it has an IP address
print(host)

# set destination port
port = 10000

# connection to hostname on the port.
s.connect((host, port))

plaintext = "0x28B4D27B225F8BD8"
C1 = addRoundKey(plaintext, k)
C2 = sBoxLayer(C1, SBOX)
C3 = pLayer(C2, pTable)
msg = C3
s.send(msg.encode())

# Receive no more than 1024 bytes
data = s.recv(1024)
reply = '...'
reply = data.decode()
reply = eval(reply)
print(reply)
D1 = decrypt_numbers(reply)
D2 = numbers_to_plaintext(D1)

print('ECHO: ' + D2)
print('Original: ' + plaintext)
if(plaintext == D2):
    print("Success!")

# Close connection
s.close()

