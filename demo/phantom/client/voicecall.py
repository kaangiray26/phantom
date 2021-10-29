#!/usr/bin/python2
#-*- encoding:utf-8 -*-
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
shared=None
voice=False

#PYAUDIO CONFIG
frames=""
CHUNK=256
RATE = 24000
FORMAT=pyaudio.paFloat32

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
      print "exiting"

##SOCKET RECEIVE
def svr_receive(sock):
  global connected
  global offset
  global frames
  global voice
  global server_encryption
  global server_ivkey
  global server_privatekey
  while True:
    if offset==True:
      break
    if voice==True:
      data=sock.recv(1024)
      if len(data)==1024:
        out.write(data,CHUNK)
      continue
    data=sock.recv(1024)
    if not data:
      break
    else:
      if server_encryption==True:
        dec=sdecrypt(data)
        data=b64decode(dec)
      if data==">Welcome to Phantom Chat!":
        print ("Connected.\n")
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
        sock.send(sencrypt("/audcll sharedkey"))
      elif data=="Goodbye.":
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        os._exit(os.EX_OK)
      elif data=="Found.":
        voice=True
        p = pyaudio.PyAudio()
        out = p.open(format=FORMAT,channels=1,rate=RATE,output=True,frames_per_buffer=CHUNK)
        inp = p.open(format=FORMAT,channels=1,rate=RATE,input=True,frames_per_buffer=CHUNK)
        vox_send(sock,inp)
        continue
      print "LEN:",len(data),data,"."

##VOICECALL SENDING AUDIO
class vox_send(Thread):
  def __init__(self,sock,stream):
    Thread.__init__(self)
    self.stream=stream
    self.sock=sock
    self.start()
  def run(self):
    while True:
      try:
        data=self.stream.read(CHUNK, exception_on_overflow=False)
        self.sock.send(data)
      except:
        pass

##VOICECALL RECEIVING AUDIO
class vox_receive(Thread):
  def __init__(self,sock,stream):
    Thread.__init__(self)
    self.stream=stream
    self.sock=sock
    self.start()
  def run(self):
    global frames
    inx=0
    while True:
      try:
        if len(frames)!=0:
          self.stream.write(frames,CHUNK)
          inx+=1024
      except:
        pass

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
os.system("clear && printf '\e[3J'")
time.sleep(0.2)
client()
