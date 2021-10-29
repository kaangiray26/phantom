#!/usr/bin/python2
#-*- encoding:utf-8 -*-
from __future__ import print_function
import readline
import os,sys
import socket
import time
from pynput import keyboard
import pyaudio
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from simplecrypt import encrypt, decrypt
from threading import Thread
from socket import AF_INET,AF_INET6,SOCK_STREAM
from thread import start_new_thread


#FILE DETAILS
f_name=None
f_dir=None
f_size=None
f_send=False
arg=sys.argv[1:]
if arg[0]=="True":
  f_name=arg[1]
  f_dir=arg[2]
  f_size=arg[3]
  f_send=True

##TERMINAL HANDLING
CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'
CSI = '\x1b['
CLEAR = CSI + '2J'
CLEAR_LINE = CSI + '2K'
SAVE_CURSOR = CSI + 's'
UNSAVE_CURSOR = CSI + 'u'
SCROLL='\x1bD'
height = 80
GOTO_INPUT = CSI + '%d;1H' % (height + 1)
GOTO_UP = CSI + '0;1H'
def emit(*args):
    print(*args, sep='', end='')
def set_scroll(n):
    return CSI + '0;%dr' % n
#emit(CLEAR, set_scroll(height))

##SERVER
HOST = 'phserver.duckdns.org'
PORT = 2662

encryption=False
ivkey=None
privatekey=None
targetname=None

server_encryption=False
server_ivkey=None
server_privatekey=None

offset=False
connected=False
transfer=False
shared=None

send_ss=True
receive_ss=False
filechunk=16384

##FILESIZE CONVERTER
sizedict={1:"B",2:"KB",3:"MB",4:"GB",5:"TB",6:"PB",7:"EB",8:"ZB",9:"YB"}
def normalize(psize):
  psize=float(psize)
  k=1
  while psize>1000:
    psize/=1000
    k+=1
  return "%s %s" %(round(psize,2),sizedict[k])

##AES CRYPTOGRAPHY
def pad(s):
  return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
  return s[0:-ord(s[-1])]

def fencrypt(text):
  text=pad(text)
  crypt = AES.new(privatekey, AES.MODE_CBC, ivkey)
  return crypt.encrypt(text)

def fdecrypt(text):
  crypt = AES.new(privatekey, AES.MODE_CBC, ivkey)
  return unpad(crypt.decrypt(text))

def xencrypt(text):
  crypt = AES.new(privatekey, AES.MODE_ECB)
  return crypt.encrypt(' '*(16-len(text)%16)+text)

def xdecrypt(text):
  crypt = AES.new(privatekey, AES.MODE_ECB)
  return crypt.decrypt(text).strip()

def sencrypt(text):
  crypt = AES.new(server_privatekey, AES.MODE_ECB)
  return crypt.encrypt(' '*(16-len(text)%16)+text)

def sdecrypt(text):
  crypt = AES.new(server_privatekey, AES.MODE_ECB)
  return crypt.decrypt(text).strip()

##RSA CRYPTOGRAPHY
def keygen():
  rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
  rsa_public_key = rsa_private_key.public_key()
  pem_private = rsa_private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
  pem_public = rsa_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
  return rsa_private_key,pem_public

def rsa_crypt(rsa_private_key,sharedkey):
  aeskey = rsa_private_key.decrypt(sharedkey, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
  return aeskey

##RESET CHAT ON ESC
def on_release(key):
  global connected
  global offset
  try:
    if key == keyboard.Key.esc:
      offset=True
      shared.shutdown(socket.SHUT_RDWR)
      os._exit(os.EX_OK)
  except:
    pass

def listen():
  listener = keyboard.Listener(on_release=on_release)
  listener.start()

##WAITING FOR EXIT SIGNAL
def exit_on_signal():
  while True:
    msg=raw_input()
    if msg=="-:$ endcall":
      pp("exiting")

##WRITE TO STDOUT
def pp(text):
  emit(SAVE_CURSOR, GOTO_UP)
  print(text)
  emit(UNSAVE_CURSOR)
  emit(SAVE_CURSOR, GOTO_INPUT, CLEAR_LINE)

pp(arg)
time.sleep(2)
##SOCKET RECEIVE
def svr_receive(sock):
  global connected
  global offset
  global transfer
  global server_encryption
  global server_ivkey
  global server_privatekey
  global encryption
  global privatekey
  global ivkey
  global targetname
  while True:
    if offset==True:
      break
    if transfer==True:
      continue
    data=sock.recv(1024)
    if not data:
      break
    else:
      if server_encryption==True:
        dec=sdecrypt(data)
        data=b64decode(dec)
      if data==">Welcome to Phantom Chat!":
        pp("Connected")
        connected=True
        rsa_private_key,pem_public=keygen()
        sock.send("$rsa-public-begin")
        sock.sendall(pem_public)
        time.sleep(0.5)
        sock.send("$rsa-public-end")
        sharedkey=sock.recv(1024)
        aeskey=rsa_crypt(rsa_private_key,sharedkey)
        server_privatekey=aeskey.split()[1]
        server_ivkey=b64encode(aeskey.split()[2])
        server_encryption=True
        sock.send(sencrypt("/audcll sharedkey %s" %(str(f_send))))
      elif data.startswith("$encrypt"):
        privatekey=data.split()[1]
        ivkey=b64decode(data.split()[2])
        encryption=True
        targetname=data.split()[3]
        transfer=True
        if f_send==True:
          sendFile(sock,f_name,f_dir,f_size)
        if f_send==False:
          receiveFile(sock,f_name,f_size,f_dir)
        continue
      elif data=="Goodbye.":
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        os._exit(os.EX_OK)

##SEND FILE
class sendFile(Thread):
  def __init__(self,sock,f_name,f_dir,f_size):
    Thread.__init__(self)
    self.sock=sock
    self.f_name=f_name
    self.f_dir=f_dir
    self.f_size=f_size
    self.start()
    self.join()
  def run(self):
    pp("Sending file...")
    f=open(self.f_dir,"rb").read()
    bf=fencrypt(b64encode(f))
    self.sock.send(xencrypt(b64encode("-:$ File:"+'##'+str(self.f_size)+'##'+self.f_name+"##"+str(len(bf)))))
    time.sleep(1)
    self.sock.sendall(bf)
    time.sleep(3)
    pp("\n>File transfer completed.")

##RECEIVE FILE
class receiveFile(Thread):
  def __init__(self,sock,f_name,f_size,b64size):
    global receive_ss
    Thread.__init__(self)
    self.sock=sock
    self.f_name=None
    self.f_size=None
    self.b64size=None
    self.start()
    self.join()
  def run(self):
    receive_ss=True
    while True:
      data=self.sock.recv(filechunk)
      dec=xdecrypt(data)
      msg=b64decode(dec)
      if msg.startswith("-:$ File:"):
        info=msg.split("##")
        self.f_size=info[1]
        self.f_name=info[2]
        self.b64size=info[3]
        break
    f=open(self.f_name,"wb")
    total=0
    b_out=""
    while receive_ss==True:
      if int(total)>=int(self.b64size):
        receive_ss=False
        break
      data=self.sock.recv(filechunk)
      b_out+=data
      total+=len(data)
      progress=int(float(total)/int(self.b64size)*100)/4
      remain=25-progress
      emit(SAVE_CURSOR, GOTO_UP)
      sys.stdout.write('\rProgress|%s|%s /%s   ' %("#"*progress+" "*remain,normalize(total),normalize(self.b64size)))
      sys.stdout.flush()
      emit(UNSAVE_CURSOR)
      emit(SAVE_CURSOR, GOTO_INPUT, CLEAR_LINE)
    pp("\n>File transfer completed.")
    pp("Decrypting file...")
    dec=fdecrypt(b_out)
    f.write(b64decode(dec))
    f.close()
    pp(">Done.")

##MAIN HANDLER
class client(Thread):
  def __init__(self):
    global connected
    global offset
    Thread.__init__(self)
    connected=False
    offset=False
    self.client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.c=0
    self.start()
    self.join()
  def run(self):
    global connected
    global offset
    global shared
    try:
      self.client.settimeout(3)
      self.client.connect((HOST,PORT))
      self.client.settimeout(None)
    except Exception as msg:
      print (msg)
      print ("Connection failed.")
      os._exit(os.EX_OK)
    #STARTER
    start_new_thread(svr_receive, (self.client,))
    start_new_thread(exit_on_signal,())
    listen()
    shared=self.client
    while True:
      self.c+=1
      if self.c>=20:
        print ("Connection failed.")
        os._exit(os.EX_OK)
      if connected==False:
        time.sleep(0.1)
      elif connected==True:
        break
    while True:
      if offset==False:
        continue
      else:
        self.client.shutdown(socket.SHUT_RDWR)
        break

##START HERE
#os.system("clear && printf '\e[3J'")
time.sleep(0.2)
emit(SAVE_CURSOR, GOTO_INPUT, CLEAR_LINE)
client()
