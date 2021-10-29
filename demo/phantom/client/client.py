#!/usr/bin/python
# -*- encoding: utf-8 -*-
from __future__ import print_function
import readline
import os
import sys
import subprocess
import signal
import socket
import time
from pynput import keyboard
import PyInquirer
from PyInquirer import style_from_dict, Token
from datetime import datetime
import hashlib
import ipaddress
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
from _thread import start_new_thread
from socket import AF_INET, AF_INET6, SOCK_STREAM
from colorama import Fore, Style

# AUTOLOGIN
loginfo = ""
arg = sys.argv[1:]
if "-i" in arg:
    try:
        import login
        if len(arg) == 1:
            us = login.credentials.keys()[0]
        elif len(arg) == 2:
            us = arg[arg.index("-i")+1]
        ps = login.credentials[us]
        loginfo = "/login %s %s" % (us, ps)
    except:
        pass

# SERVER
HOST = 'phserver.duckdns.org'
PORT = 2662

setexit = False
connected = False
offset = False
cutback = False
online = False

encryption = False
ivkey = None
privatekey = None
targetname = None

server_encryption = False
server_ivkey = None
server_privatekey = None

voiceCall = False
videoCall = False
sendingFile = False
audcll = None

send_ss = True
receive_ss = False
filechunk = 1048576

# PyInquirer CONFIG
usr = [
    {'type': 'input',
     'name': 'opt',
     'message': '-:$ Enter username:'
     }
]
pwd = [
    {'type': 'password',
     'name': 'opt',
     'message': '-:$ Enter password:'
     }
]
custom_style_1 = style_from_dict({
    Token.Separator: '#cc5454',
    Token.QuestionMark: '#673ab7 bold',
    Token.Selected: '#cc5454',  # default
    Token.Pointer: '#673ab7 bold',
    Token.Instruction: '',  # default
    Token.Answer: '#f44336 bold',
    Token.Question: '',
})
custom_style_2 = style_from_dict({
    Token.Separator: '#6C6C6C',
    Token.QuestionMark: '#FF9D00 bold',
    # Token.Selected: '',  # default
    Token.Selected: '#5F819D',
    Token.Pointer: '#FF9D00 bold',
    Token.Instruction: '',  # default
    Token.Answer: '#5F819D bold',
    Token.Question: '',
})

# TERMINAL HANDLING
CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'
CSI = '\x1b['
CLEAR = CSI + '2J'
CLEAR_LINE = CSI + '2K'
SAVE_CURSOR = CSI + 's'
UNSAVE_CURSOR = CSI + 'u'
SCROLL = '\x1bD'
height = 80
GOTO_INPUT = CSI + '%d;1H' % (height + 1)
GOTO_UP = CSI + '0;1H'


def emit(*args):
    print(*args, sep='', end='')


def set_scroll(n):
    return CSI + '0;%dr' % n


emit(CLEAR, set_scroll(height))

# FILESIZE CONVERTER
sizedict = {1: "B", 2: "KB", 3: "MB", 4: "GB",
            5: "TB", 6: "PB", 7: "EB", 8: "ZB", 9: "YB"}


def normalize(psize):
    psize = float(psize)
    k = 1
    while psize > 1000:
        psize /= 1000
        k += 1
    return "%s %s" % (round(psize, 2), sizedict[k])

# AES CRYPTOGRAPHY


def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def unpad(s):
    return s[0:-ord(s[-1])]


def fencrypt(text):
    text = pad(text)
    crypt = AES.new(privatekey, AES.MODE_CBC, ivkey)
    return crypt.encrypt(text)


def fdecrypt(text):
    crypt = AES.new(privatekey, AES.MODE_CBC, ivkey)
    return unpad(crypt.decrypt(text))


def xencrypt(text):
    crypt = AES.new(privatekey, AES.MODE_ECB)
    return crypt.encrypt(' '*(16-len(text.decode()) % 16)+text.decode())


def xdecrypt(text):
    crypt = AES.new(privatekey, AES.MODE_ECB)
    return crypt.decrypt(text).strip()


def sencrypt(text):
    crypt = AES.new(server_privatekey, AES.MODE_ECB)
    return crypt.encrypt(' '*(16-len(text) % 16)+text)


def sdecrypt(text):
    crypt = AES.new(server_privatekey, AES.MODE_ECB)
    return crypt.decrypt(text).strip()

# RSA CRYPTOGRAPHY


def keygen():
    rsa_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())
    rsa_public_key = rsa_private_key.public_key()
    pem_private = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    pem_public = rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return rsa_private_key, pem_public


def rsa_crypt(rsa_private_key, sharedkey):
    aeskey = rsa_private_key.decrypt(sharedkey, padding.OAEP(mgf=padding.MGF1(
        algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return aeskey

# EXIT CHAT ON ESC


def on_release(key):
    global connected
    global encryption
    global privatekey
    global ivkey
    global targetname
    global offset
    global loginfo
    try:
        if key == keyboard.Key.esc:
            os.system("clear && printf '\e[3J'")
            emit(GOTO_INPUT)
            print(Style.BRIGHT+Fore.GREEN+"Reset."+Style.RESET_ALL)
            shared.sock.shutdown(socket.SHUT_RDWR)
            os._exit(os.EX_OK)
    except:
        pass


def listen():
    listener = keyboard.Listener(on_release=on_release)
    listener.start()

# SOCKET RECEIVE


def svr_receive(sock):
    global online
    global connected
    global encryption
    global server_encryption
    global server_ivkey
    global server_privatekey
    global privatekey
    global ivkey
    global targetname
    global offset
    global loginfo
    global p
    global voiceCall
    global videoCall
    global audcll
    global vidcll
    while True:
        if offset == True:
            break
        data = sock.recv(1024)
        if not data:
            break
        else:
            if encryption == False:
                if server_encryption == True:
                    dec = sdecrypt(data)
                    data = b64decode(dec)
                data = data.decode()
                if data == ">Welcome to Phantom Chat!":
                    print(Style.BRIGHT+Fore.GREEN +
                          "Connected.\n"+data+Style.RESET_ALL)
                    connected = True
                    rsa_private_key, pem_public = keygen()
                    sock.send("$rsa-public-begin".encode())
                    sock.sendall(pem_public)
                    time.sleep(0.5)
                    sock.send("$rsa-public-end".encode())
                    sharedkey = sock.recv(1024)
                    aeskey = rsa_crypt(rsa_private_key, sharedkey)
                    server_privatekey = aeskey.split()[1]
                    server_ivkey = b64encode(aeskey.split()[2])
                    server_encryption = True
                    if loginfo != "":
                        print(Style.BRIGHT+Fore.RED +
                              "Logging in user...\n"+Style.RESET_ALL)
                        sock.send(sencrypt(loginfo))
                elif data.startswith("$encrypt"):
                    privatekey = data.split()[1]
                    ivkey = b64decode(data.split()[2])
                    encryption = True
                    targetname = data.split()[3]
                    jetzt = False
                    print(Style.BRIGHT+Fore.RED+'>Chatting with %s!' %
                          (targetname)+Style.RESET_ALL)
                    sock.send(".".encode())
                elif data == "Goodbye.":
                    print(Style.BRIGHT+Fore.GREEN+data+Style.RESET_ALL)
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    os._exit(os.EX_OK)
                elif data.startswith("-:$ Logged in as:"):
                    online = True
                    print(Style.BRIGHT+Fore.GREEN+data+Style.RESET_ALL)
                else:
                    print(Style.BRIGHT+Fore.GREEN+data+Style.RESET_ALL)
            else:
                if jetzt == False:
                    jetzt = True
                else:
                    if data.startswith('-:$ '.encode()):
                        print(Style.BRIGHT+Fore.RED+data+Style.RESET_ALL)
                    else:
                        try:
                            dec = xdecrypt(data)
                            enc_msg = b64decode(dec)
                            enc_msg = enc_msg.decode()
                        except TypeError:
                            continue
                        if enc_msg == "-:$ exitsignal":
                            print(Style.BRIGHT+Fore.RED +
                                  'Exiting...'+Style.RESET_ALL)
                            sock.send("-:$ exit".encode("utf-8"))
                            privatekey = None
                            encryption = False
                            oldt = targetname
                            targetname = None
                            offset = False
                            print(Style.BRIGHT+Fore.RED+'%s closed the chat.' %
                                  (oldt)+Style.RESET_ALL)
                        elif enc_msg == "-:$ endcall":
                            if voiceCall:
                                print(Style.BRIGHT+Fore.RED +
                                      'Exiting voicecall...'+Style.RESET_ALL)
                                #os.killpg(os.getpgid(audcll.pid), signal.SIGTERM)
                                audcll.stdin.write('-:$ endcall\n')
                                os.kill(audcll.pid, signal.SIGTERM)
                                voiceCall = False
                                audcll = None
                            if videoCall:
                                print(Style.BRIGHT+Fore.RED +
                                      'Exiting videocall...'+Style.RESET_ALL)
                                #os.killpg(os.getpgid(vidcll.pid), signal.SIGTERM)
                                grep_stdout = vidcll.communicate(
                                    input=b'-:$ endcall')[0]
                                print(grep_stdout.decode())
                                os.kill(vidcll.pid, signal.SIGTERM)
                                videoCall = False
                                vidcll = None
                            print(Style.BRIGHT+Fore.RED+'%s closed the call.' %
                                  (targetname)+Style.RESET_ALL)
                        elif enc_msg == "-:$ voicecall":
                            print(Style.BRIGHT+Fore.RED +
                                  ">Starting voice call..."+Style.RESET_ALL)
                            # audcll=subprocess.Popen("./voicecall.py", shell=True, stdout=open(os.devnull,'wb'), stderr=subprocess.STDOUT) #, preexec_fn=os.setsid)
                            audcll = subprocess.Popen(
                                "./voicecall.py", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            voiceCall = True
                            continue
                        # VIDEOCALL
                        elif enc_msg == "-:$ videocall":
                            print(Style.BRIGHT+Fore.RED +
                                  ">Starting video call..."+Style.RESET_ALL)
                            shared.video = True
                            time.sleep(3)
                            import videocall
                            continue
                        elif enc_msg.startswith("-:$ filetransfer"):
                            print("Getting File")
                            print("./sendfile.py False")
                            receivef = subprocess.Popen(
                                "./sendfile.py False", shell=True, stdin=subprocess.PIPE, stdout=sys.stdout, stderr=subprocess.PIPE)
                            # info=b64decode(dec).split("##")
                            # f_size=info[1]
                            # f_name=info[2]
                            # b64size=info[3]
                            #print (Style.BRIGHT+Fore.RED+"Getting file:"+Fore.CYAN+f_name+Fore.RED+" Size:"+Fore.CYAN+f_size+Fore.RED+" bytes"+Style.RESET_ALL)
                            # receiveFile(sock,f_name,f_size,b64size)
                            #receivef=subprocess.Popen("./sendfile.py False" %(f_name,b64size,f_size), shell=True,stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            #emit(SAVE_CURSOR, GOTO_UP)
                            # emit(UNSAVE_CURSOR)
                        else:
                            emit(SAVE_CURSOR, GOTO_INPUT)
                            print(Style.BRIGHT+'    [%s]' % (time.strftime('%H:%M:%S'))+'<' +
                                  Fore.WHITE+targetname+Fore.RESET+'> '+Fore.YELLOW+enc_msg+Style.RESET_ALL)
                            emit(UNSAVE_CURSOR)

# SOCKET SEND


def svr_send(sock):
    global connected
    global encryption
    global server_encryption
    global privatekey
    global targetname
    global offset
    global p
    global loginfo
    global voiceCall
    global videoCall
    global audcll
    global vidcll
    while True:
        emit(SAVE_CURSOR, GOTO_INPUT, CLEAR_LINE)
        try:
            text = input("").strip()
        except ValueError:
            continue
        finally:
            emit(UNSAVE_CURSOR)
        if text:
            if encryption == True:
                if text == "/exit":
                    print(Style.BRIGHT+Fore.RED+'Exiting...'+Style.RESET_ALL)
                    sock.send(xencrypt(b64encode('-:$ exitsignal'.encode("utf-8"))))
                    sock.send("-:$ exit".encode("utf-8"))
                    privatekey = None
                    encryption = False
                    targetname = None
                    offset = False
                    print(Style.BRIGHT+Fore.RED +
                          'You closed the chat.'+Style.RESET_ALL)
                elif text == "/endcall":
                    sock.send(xencrypt(b64encode('-:$ endcall'.encode("utf-8"))))
                    if voiceCall:
                        print(Style.BRIGHT+Fore.RED +
                              'Exiting voicecall...'+Style.RESET_ALL)
                        audcll.stdin.write('-:$ endcall\n')
                        time.sleep(2)
                        os.kill(audcll.pid, signal.SIGTERM)
                        voiceCall = False
                        audcll = None
                    if videoCall:
                        print(Style.BRIGHT+Fore.RED +
                              'Exiting videocall...'+Style.RESET_ALL)
                        grep_stdout = vidcll.communicate(
                            input=b'-:$ endcall')[0]
                        print(grep_stdout.decode())
                        os.kill(vidcll.pid, signal.SIGTERM)
                        videoCall = False
                        vidcll = None
                    print(Style.BRIGHT+Fore.RED +
                          'You ended the call.'+Style.RESET_ALL)
                elif text == "/voicecall":
                    print(Style.BRIGHT+Fore.RED +
                          ">Starting voice call..."+Style.RESET_ALL)
                    sock.send(xencrypt(b64encode('-:$ voicecall'.encode("utf-8"))))
                    audcll = subprocess.Popen(
                        "./voicecall.py", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    voiceCall = True
                    continue
                elif text == "/videocall":
                    print(Style.BRIGHT+Fore.RED +
                          ">Starting video call..."+Style.RESET_ALL)
                    sock.send(xencrypt(b64encode('-:$ videocall'.encode("utf-8"))))
                    shared.video = True
                    time.sleep(3)
                    import videocall
                    continue
                elif text == "/sendfile":
                    f_dir = raw_input("Drop file here:")
                    if f_dir.startswith("'") and f_dir.endswith("'"):
                        f_dir = f_dir[1:-1]
                    if os.path.exists(f_dir) == True:
                        f_size = os.path.getsize(f_dir)
                        f_name = os.path.basename(f_dir)
                        # sendFile(sock,f_name,f_dir,f_size)
                        sock.send(xencrypt(b64encode('-:$ filetransfer'.encode("utf-8"))))
                        print("Sending file")
                        print("./sendfile.py True %s %s %s" %
                              (f_name, f_dir, f_size))
                        sendf = subprocess.Popen("./sendfile.py True '%s' '%s' '%s'" % (
                            f_name, f_dir, f_size), shell=True, stdin=subprocess.PIPE, stdout=sys.stdout, stderr=subprocess.PIPE)
                    else:
                        print(Style.BRIGHT+Fore.RED +
                              "File not found!"+Style.RESET_ALL)
                else:
                    msg = xencrypt(b64encode(text.encode("utf-8")))
                    sock.send(msg)
            else:
                if offset == True:
                    break
                if text == "/login" and online == False:
                    emit(SAVE_CURSOR, GOTO_INPUT, CLEAR_LINE)
                    us = PyInquirer.prompt(usr, style=custom_style_1)['opt']
                    ps = PyInquirer.prompt(pwd, style=custom_style_1)['opt']
                    text = "/login %s %s" % (us, ps)
                    loginfo = text
                    emit(UNSAVE_CURSOR)
                try:
                    if server_encryption == True:
                        text = sencrypt(text)
                    sock.send(text)
                except socket.error:
                    break

# SEND FILE


class sendFile(Thread):
    def __init__(self, sock, f_name, f_dir, f_size):
        Thread.__init__(self)
        self.sock = sock
        self.f_name = f_name
        self.f_dir = f_dir
        self.f_size = f_size
        self.start()
        self.join()

    def run(self):
        print(Style.BRIGHT+Fore.RED+"Sending file..."+Style.RESET_ALL)
        f = open(self.f_dir, "rb").read()
        bf = fencrypt(b64encode(f))
        self.sock.send(xencrypt(b64encode("-:$ File:"+'##' +
                                          str(self.f_size)+'##'+self.f_name+"##"+str(len(bf)))))
        self.sock.sendall(bf)
        time.sleep(3)
        print(Style.BRIGHT+Fore.RED+"\n>File transfer completed."+Style.RESET_ALL)


# RECEIVE FILE
class receiveFile(Thread):
    def __init__(self, sock, f_name, f_size, b64size):
        global receive_ss
        Thread.__init__(self)
        self.sock = sock
        self.f_name = f_name
        self.f_size = f_size
        self.b64size = b64size
        self.start()
        self.join()

    def run(self):
        receive_ss = True
        f = open(self.f_name, "wb")
        total = 0
        b_out = ""
        while receive_ss == True:
            if int(total) >= int(self.b64size):
                receive_ss = False
                break
            data = self.sock.recv(filechunk)
            b_out += data
            total += len(data)
            progress = int(float(total)/int(self.b64size)*100)/4
            remain = 25-progress
            sys.stdout.write('\rProgress|%s|%s /%s   ' % ("#"*progress +
                                                          " "*remain, normalize(total), normalize(self.b64size)))
            sys.stdout.flush()
        print(Style.BRIGHT+Fore.RED+"\n>File transfer completed."+Style.RESET_ALL)
        print(Style.BRIGHT+Fore.MAGENTA+"Decrypting file..."+Style.RESET_ALL)
        dec = fdecrypt(b_out)
        f.write(b64decode(dec))
        f.close()
        print(Style.BRIGHT+Fore.RED+"\n>Done."+Style.RESET_ALL)


# MAIN HANDLER
class client(Thread):
    def __init__(self):
        global connected
        global offset
        Thread.__init__(self)
        connected = False
        offset = False
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.c = 0
        self.start()
        self.join()

    def run(self):
        global connected
        global offset
        try:
            self.client.settimeout(3)
            self.client.connect((HOST, PORT))
            self.client.settimeout(None)
        except Exception as msg:
            print(msg)
            print(Style.BRIGHT+Fore.RED+"Connection failed."+Style.RESET_ALL)
            os._exit(os.EX_OK)
        start_new_thread(svr_receive, (self.client,))
        start_new_thread(svr_send, (self.client,))
        listen()
        while True:
            self.c += 1
            if self.c >= 20:
                print(Style.BRIGHT+Fore.RED+"Connection failed."+Style.RESET_ALL)
                os._exit(os.EX_OK)
            if connected == False:
                time.sleep(0.1)
            elif connected == True:
                break
        while True:
            if offset == True:
                self.client.shutdown(socket.SHUT_RDWR)
                break


# START HERE
os.system("clear && printf '\e[3J'")
time.sleep(0.2)
emit(GOTO_INPUT)
print(Style.BRIGHT+Fore.WHITE+"Connecting to: <%s>..." %
      (HOST)+Style.RESET_ALL)
while setexit == False:
    client()
