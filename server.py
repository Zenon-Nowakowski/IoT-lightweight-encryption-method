import socket                                         
from main import * 
# create a TCP/IP socket object
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

hostname=socket.gethostname()   
IPAddr=socket.gethostbyname(hostname) 
# my IP 
host = IPAddr                         

#set port number for this server
port = 10000                                          

# bind to the port
serversocket.bind((host, port))

# Listen for incoming connections, queue up to 5 requests
serversocket.listen(5)                                           

while True:
   # wait for a connection
   print('waiting for a connetion on port ' + str(port) + '\n')
   clientsocket,addr = serversocket.accept()      

   #Confirm connection to client
   print("Got a connection from " + str(addr))
   #Collect data from client
   data = clientsocket.recv(1024)
   #if statement for recieving data 
   if data: 
      print("recieved: " + data.decode())
      reply = '...'
      reply = data.decode()
      #decode
      D1 = pLayer(reply, pTable)
      D2 = sBoxDecrypt(D1, SBOX_INVERSE)
      D3 = addRoundKey(D2, k)
      
      C1 = plaintext_numbers(D3)
      C2 = ciphertext_numbers(C1)
      C2 = str(C2)
      clientsocket.send(C2.encode())
      break
   else:
      print('no more data from' + str(addr))
      break

   clientsocket.close()

