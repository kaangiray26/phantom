#!/usr/bin/python
#-*- encoding:utf-8 -*-
import os,sys
import pymysql
import socket
import subprocess
import hashlib
import base64
import ipaddress
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode
from cryptography.fernet import Fernet
from threading import Thread
from socket import AF_INET,AF_INET6,SOCK_STREAM
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import time

os.system("lsof -t -i tcp:2662 | xargs kill -9 > /dev/null 2>&1")

user_cmd=['/whoami','/help','/exit','/check','/tell','/chat','/accept','/channels','/join']
guest_cmd=['/login','/register','/whoami','/help','/exit','/audcll','/vidcll','/postf']
admin_cmd=['\n',"",'/help','/stop','/users','/mail','/guests','/check','/hostname']

svr_name="phserver.duckdns.org"
HOST6=os.popen('sudo ifconfig | grep -i "inet6 2"').read().splitlines()
HOST4=os.popen('sudo ifconfig | grep -i "inet "').read().splitlines()[1].split()[1]
ipv4=os.popen('curl -s ipv4.icanhazip.com').read().strip()
ipv6=os.popen('curl -s icanhazip.com').read().strip()

hlp=open('admin_help.conf','r').read().splitlines()
u_hlp=open('user_help.conf','r').read().strip()
g_hlp=open('guest_help.conf','r').read().strip()
chnlist=open('channels.conf','r').read().splitlines()

ph=PasswordHasher()

connected={}
active_users={}
user_keys={}
thread_kill={}
accepts={}
mailbox={}
channels={}
chatting={}
voicecall={}
transfer_keys={}

print ("\n...-Phantom Chat-...")
HOST=HOST4
print (HOST)
PORT = 2662

##Create channels
for ch in chnlist:
  channels[ch]={}

##RSA CRYPTOGRAPHY
def rsa_crypt(pem_public):
  rsa_public_key = serialization.load_pem_public_key(pem_public, backend=default_backend())
  key=keygen()
  iv_key=iv()
  message='$encrypt '+key.decode('latin1').encode("utf-8")+' '+iv_key
  encrypted = rsa_public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
  return key,iv_key,encrypted

##AES CRYPTOGRAPHY
def keygen():
  return b64encode(os.urandom(16)).decode('utf-8')

def iv():
  return b64encode(Random.new().read(16))

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

def sencrypt(key,text):
  text=b64encode(text)
  crypt = AES.new(key, AES.MODE_ECB)
  return crypt.encrypt(' '*(16-len(text)%16)+text)

def sdecrypt(key,text):
  crypt = AES.new(key, AES.MODE_ECB)
  return crypt.decrypt(text).strip()

##USERNAME CHECK
def chk_alive(name):
  c="SELECT * from iplist where username='%s'" %(name)
  cursor.execute(c)
  result=cursor.fetchall()
  if len(result)==0:
    return "-:$ User not found!"
  else:
    if name in active_users.keys():
      return "-:$ User is online"
    else:
      return "-:$ Offline.\nLast login:%s" %(result[0][3])

##MariaDB CONNECTION
def ConnectDatabase():
    import db_config
    user_id = db_config.credentials["user"]
    pass_id = db_config.credentials["password"]
    db = pymysql.connect(host="localhost", user=user_id, password=pass_id, database="phantom", charset='utf8', use_unicode=True)
    cursor=db.cursor()
    return db, cursor
db, cursor = ConnectDatabase()
print ("-:$ Connection to database established.")

##USERNAME AVAILABLE CHECK
def inuse(name):
  cursor.execute("SELECT * from userlist where username='%s'" %(name))
  result=cursor.fetchall()
  if len(result)==0:
    return False
  else:
    print ("USER:",result[0])
    return True

##LAST_ONLINE UPDATE
def update_ip(user,addr,status):
  addr="Classified"
  timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
  c1="DELETE FROM iplist WHERE username='%s'" %(user)
  cursor.execute(c1)
  db.commit()
  c2="INSERT INTO iplist VALUES('%s', '%s', '%s', '%s')" %(user,addr,status,timestamp)
  cursor.execute(c2)
  db.commit()

##USER GET
def get_ip(user):
  cursor.execute("SELECT * from iplist where username='%s'" %(user))
  result=cursor.fetchall()
  return result[0][1]

##LOGIN USER
def login(user,passwd):
  cursor.execute("SELECT * from userlist where username='%s'" %(user))
  result=cursor.fetchall()
  if len(result)==0:
    return {'status':False}
  else:
    result=result[0]
    hash,salt=(result[1],result[2])
    try:
      ph.verify(hash, passwd+salt)
      return {'status':True,'username':user}
    except VerifyMismatchError:
      return {'status':False}

##ADD USER TO DATABASE
def add_db(user,passwd):
  salt=b64encode(os.urandom(64)).decode('utf-8')
  hash=ph.hash(passwd+salt)
  c="INSERT INTO userlist VALUES('%s', '%s', '%s')" %(user,hash,salt)
  print (c)
  try:
    cursor.execute(c)
    db.commit()
    return True
  except:
    return False

class handler(Thread):
  def __init__(self,selfname,selfsock,targetname,targetsock,addr):
    Thread.__init__(self)
    self.username=selfname
    self.sock=selfsock
    self.targetname=targetname
    self.targetsock=targetsock
    self.addr=addr
    self.start()

  def run(self):
    print ("connecting:",self.sock,self.targetsock)
    #chat1(self.username,self.sock,self.targetname,self.targetsock,self.addr)
    chat2(self.username,self.sock,self.targetname,self.targetsock,self.addr)

class chat1(Thread):
  #WHY IS THIS HERE
  #I DON'T REMEMBER WHY I MADE THIS FUNCTION AT ALL!
  def __init__(self,selfname,selfsock,targetname,targetsock,addr):
    Thread.__init__(self)
    self.username=selfname
    self.sock=selfsock
    self.targetname=targetname
    self.targetsock=targetsock
    self.addr=addr
    self.start()

  def run(self):
    while True:
      if self.username not in chatting.keys():
        break
      message=sys.stdin.readline().strip()
      message=message
      self.targetsock.send(message)

class chat2(Thread):
  def __init__(self,selfname,selfsock,targetname,targetsock,addr):
    Thread.__init__(self)
    self.username=selfname
    self.sock=selfsock
    self.targetname=targetname
    self.targetsock=targetsock
    self.addr=addr
    self.start()

  def run(self):
    global chatting
    global accepts
    global thread_kill
    while True:
      #if self.username not in chatting.keys():
      #  break
      try:
        msg = str(self.targetsock.recv(16384))
      except socket.timeout:
        break
      if not msg:
        break
      else:
        if msg != None:
          msg=msg
          if msg=="-:$ exit":
            print ("Got exit msg:"+self.username+"\n")
            break
          self.sock.send(msg)
    chatting[self.targetname]=False
    accepts[self.targetname][self.username]='False'
    thread_kill[self.targetname]=False

class admin(Thread):
  def __init__(self,sock):
    Thread.__init__(self)
    self.sock=sock
    self.start()
  def run(self):
    while True:
      command=sys.stdin.readline().strip()
      if len(command)==0 or command.split()[0] not in admin_cmd:
        print ("-:$ Invalid command, type /help for help.")
      else:
        if command=="/stop":
          break
        if command=="/hostname":
          print (server.getsockname()[0])
        if command.startswith("/check"):
          try:
            username=command.split()[1]
            print (chk_alive(username))
          except IndexError:
            print ("No username given!")
        elif command=="/help":
          for i in hlp:
            print (i)
        elif command=="/users":
          print ("-:$ Connected users: ")
          for i in active_users.keys():
            print (i)
        elif command=="/guests":
          print ("-:$ Connected guests: ")
          for i in connected.keys():
            print (i, connected[i]['ip'], connected[i]['sock'])
        elif command=="/mail":
          if len(mailbox.keys())==0:
            print ("-:$ Your Mailbox is empty.")
          else:
            print ("\n-:$ Mailbox:\n",)
            for i in mailbox:
              print (i,mailbox[i])
        if len(command) != 0:
          print ("")
    self.sock.shutdown(socket.SHUT_RDWR)
    self.sock.close()
    os._exit(os.EX_OK)

class client(Thread):
  def __init__(self,sock,addr):
    print ('-:$ Connection from: %s' %(str(addr[0])))
    keys_connected=connected.keys()
    keys_connected=sorted(keys_connected)
    if len(keys_connected)==0:
      idx=1
    else:
      idx=keys_connected[-1]+1
    connected[idx]={"ip":str(addr[0]),"sock":sock}
    Thread.__init__(self)
    self.idx=idx
    self.sock=sock
    self.addr=addr
    self.start()
    self.username="guest"
    self.secured=False
    self.offset=False
    self.sock.settimeout(600.0)
  def run(self):
    global offset
    global voicecall
    global accepts
    self.sock.send('>Welcome to Phantom Chat!'.encode())
    while True:
      try:
        if self.username in chatting.keys() and chatting[self.username]==True:
          continue
      except AttributeError as e:
        print ("ERROR FOUND",e)
        print (self.sock)
      #try:
      #  if self.offset==True:
      #    break
      #except AttributeError:
      #  break
      try:
        data = str(self.sock.recv(2048))
      except socket.timeout:
        break
      if not data:
        break
      else:
        if data=="$rsa-public-begin":
          pem=""
          while True:
            tt=str(self.sock.recv(1024))
            if tt=="$rsa-public-end":
              break
            else:
              pem+=tt
          print ("rsa_public done.")
          self.key,self.iv_key,message=rsa_crypt(pem)
          self.sock.send(message)
          self.secured=True
          continue
        if self.secured==True:
          data=sdecrypt(self.key,data)
        else:
          return
        print (self.username,data)
        if self.username=="guest" and data.split()[0] not in guest_cmd:
          self.sock.send(sencrypt(self.key,"-:$ Invalid command, type /help for help."))
        elif self.username!="guest" and data.split()[0] not in user_cmd:
          self.sock.send(sencrypt(self.key,"-:$ Invalid command, type /help for help."))
        else:
          if data=="/help":
            if self.username=="guest":
              self.sock.send(sencrypt(self.key,"-:$ "+g_hlp+"\n"))
            else:
              self.sock.send(sencrypt(self.key,"-:$ "+u_hlp+"\n"))
          elif data=="/exit":
            break
          elif data=="/channels":
            self.sock.send(sencrypt(self.key,"-:$ Channel list:"))
            for ch in chnlist:
              print ("Channel:",ch)
              time.sleep(0.5)
              self.sock.send(sencrypt(self.key,ch))
          elif data.startswith("/join"):
            if self.username=="guest":
              self.sock.send(sencrypt(self.key,"-:$ Please log in first."))
            else:
              try:
                ch=data.split()[1]
                if ch not in chnlist:
                  self.sock.send(sencrypt(self.key,"-:$ Channel not found."))
                else:
                  channels[ch][self.username]=True
                  self.sock.send(sencrypt(self.key,"-:$ Joined %s" %(ch)))
              except IndexError:
                self.sock.send(sencrypt(self.key,"-:$ No channel name given!"))
          elif data.startswith("/accept"):
            if self.username=="guest":
              self.sock.send(sencrypt(self.key,"-:$ Please log in first."))
              continue
            try:
              username=data.split()[1]
              if username in active_users.keys():
                accepts[self.username][username]='True'
                time.sleep(1)
                thread_kill[self.username]=True
                #self.offset=True
                chatting[self.username]=True
                handler(self.username,self.sock,username,active_users[username],self.addr)
              else:
                self.sock.send(sencrypt(self.key,"-:$ %s is not connected to the server." %(username)))
            except IndexError:
              self.sock.send(sencrypt(self.key,"-:$ No username given!"))
          elif data.startswith("/check"):
            try:
              username=data.split()[1]
              self.sock.send(sencrypt(self.key,chk_alive(username)))
            except IndexError:
              self.sock.send(sencrypt(self.key,"-:$ No username given!"))
          elif data==("/chat"):
            if self.username=="guest":
              self.sock.send(sencrypt(self.key,"-:$ Please log in first."))
            else:
              self.sock.send(sencrypt(self.key,"-:$ With whom?"))
              username=sdecrypt(self.key,str(self.sock.recv(1024))).decode()
              print ("Username:",username)
              if username in active_users.keys():
                self.sock.send(sencrypt(self.key,"-:$ Waiting for %s to accept your request" %(username)))
                active_users[username].send(sencrypt(user_keys[username],'-:$ '+self.username+' wants to chat with you.'))
                active_users[username].send(sencrypt(user_keys[username],'-:$ Type /accept %s to join chat.' %(self.username)))
                accepted=False
                for i in range(0,30):
                  if self.username not in accepts[username].keys():
                    accepted=False
                    time.sleep(1)
                  elif accepts[username][self.username]!='True':
                    accepted=False
                    time.sleep(1)
                  elif accepts[username][self.username]=='True':
                    accepted=True
                    break
                if accepted==True:
                  self.sock.send(sencrypt(self.key,'-:$ %s accepted your request.'%(username)))
                  key=keygen()
                  iv_key=iv()
                  time.sleep(1)
                  self.sock.send(sencrypt(self.key,'$encrypt '+key.decode('latin1').encode("utf-8")+' '+iv_key+' '+username))
                  active_users[username].send(sencrypt(user_keys[username],'$encrypt '+key.decode('latin1').encode("utf-8")+' '+iv_key+' '+self.username))
                  thread_kill[self.username]=True
                  #self.offset=True
                  chatting[self.username]=True
                  handler(self.username,self.sock,username,active_users[username],self.addr)
                elif accepted==False:
                  self.sock.send(sencrypt(self.key,"-:$ %s not accepted your request" %(username)))
              else:
                self.sock.send(sencrypt(self.key,"-:$ %s is not connected to server" %(username)))
          elif data=="/whoami":
            txt="-:$ "+self.username+': ('+str(self.addr[0])+') on '+svr_name
            self.sock.send(sencrypt(self.key,txt))
          elif data.startswith("/login"):
            if len(data.split())!=3:
              self.sock.send(sencrypt(self.key,"-:$ Invalid format!"))
              continue
            username=data.split()[1]
            password=data.split()[2]
            response=login(username,password)
            if response['status']==False:
              self.sock.send(sencrypt(self.key,"-:$ Login failed!"))
            else:
              self.username=response['username']
              update_ip(self.username,self.addr[0],'online')
              active_users[self.username]=self.sock
              user_keys[self.username]=self.key
              thread_kill[self.username]=False
              accepts[self.username]={}
              try:
                del connected[self.idx]
              except KeyError:
                pass
              self.sock.send(sencrypt(self.key,"-:$ Logged in as: "+self.username))
          elif data=="/register":
            self.sock.send(sencrypt(self.key,"-:$ Enter username:"))
            for i in range(0,3):
              username=sdecrypt(self.key,str(self.sock.recv(1024).decode('utf-8').encode('latin1')))
              if inuse(username) == True:
                self.sock.send(sencrypt(self.key,"-:$ Username is in use!"))
                self.sock.send(sencrypt(self.key,"-:$ Enter another username:"))
                username=False
              else:
                break
            if username!=False:
              self.sock.send(sencrypt(self.key,"-:$ Enter password:"))
              password=sdecrypt(self.key,str(self.sock.recv(1024).decode('utf-8').encode('latin1')))
              if add_db(username,password) == True:
                self.sock.send(sencrypt(self.key,"-:$ Account created."))
                self.sock.send(sencrypt(self.key,'-:$ Please login using /login'))
              else:
                self.sock.send(sencrypt(self.key,"-:$ An Error has occured!"))
            else:
              self.sock.send(sencrypt(self.key,"\n-:$ Register failed!"))
          elif data=="/tell":
            self.sock.send(sencrypt(self.key,"-:$ Enter your message to server:"))
            msg=sdecrypt(self.key,str(self.sock.recv(1024).decode()))
            m_index=len(mailbox.keys())+1
            mailbox[m_index]={'user:':self.username,'addr:':str(self.addr[0]),'message':msg,'datetime':time.strftime('%D-%H:%M:%S')}
            self.sock.send(sencrypt(self.key,"-:$ Message sent."))
          elif data.startswith('/audcll'):
            transfer_keys[self.sock]=self.key
            print ("AUDIOCALL!")
            try:
              audkey=data.split()[1]
              voicecall[self.sock]=audkey
            except IndexError:
              self.offset==False
              break
            found=False
            for i in range(0,15):
              for g in voicecall.keys():
                if g!=self.sock and voicecall[g]==audkey:
                  target_sock=g
                  found=True
                  break
              time.sleep(0.2)
            if found==True:
              print ("Found",g)
              #self.offset=True
              #self.sock.send(sencrypt(self.key,"Found."))
              time.sleep(0.5)
              if len(data.split())==3:
                if data.split()[2]=="True":
                  print ("TRUE FOUND")
                  key=keygen()
                  iv_key=iv()
                  time.sleep(1)
                  target_sock.send(sencrypt(transfer_keys[target_sock],'$encrypt '+key.decode('latin1').encode("utf-8")+' '+iv_key+' '+"guest"))
                  self.sock.send(sencrypt(self.key,'$encrypt '+key.decode('latin1').encode("utf-8")+' '+iv_key+' '+"guest"))
                else:
                  time.sleep(1)
              chatting[self.username]=True
              if len(data.split())!=3:
                self.sock.send(sencrypt(self.key,"Found."))
              handler("guest",self.sock,"guest",target_sock,self.addr)
            else:
              self.offset==False
              break
    try:
      if self.offset==False:
        self.sock.send(sencrypt(self.key,"Goodbye."))
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        if self.username!="guest":
          try:
            del active_users[self.username]
          except KeyError:
            pass
          update_ip(self.username,self.addr[0],'offline')
        else:
          try:
            del connected[self.idx]
          except KeyError:
            pass
    except AttributeError:
      pass
try:
  server=socket.socket(AF_INET, SOCK_STREAM,0)
  server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  server.bind((HOST,PORT))
  print ('-:$ Socket bind successful on: '+HOST)
except socket.error as msg:
  print ('-:$ Bind failed. \nError Code : ' + str(msg[0]) + ' Message ' + msg[1])
  os._exit(os.EX_OK)

server.listen(10)
print ("-:$ Listening...")

while True:
  try:
    admin(server)
    conn, addr = server.accept()
    client(conn,addr)
    print ("client again!")
  except KeyboardInterrupt:
    print ("\nbye.")
    os._exit(os.EX_OK)
