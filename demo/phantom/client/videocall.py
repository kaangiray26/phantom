#!/usr/bin/python
#-*- encoding: utf-8 -*-
from __future__ import print_function
import os,sys
import socket
import time
from threading import Thread
import cv2
import numpy as np
import shared

#VIDEOCALL SENDING VIDEO
class vid_send(Thread):
  def __init__(self):
    Thread.__init__(self)
    self.start()
  def run(self):
    cap = cv2.VideoCapture(0)
    while(True):
      if shared.video==False:
        cap.release()
        break
      try:
        ret, frame = cap.read()
        data=frame.tostring()
        shared.sock.send(data)
      except:
        pass

#VIDEOCALL RECEIVING VIDEO
class vid_receive(Thread):
  def __init__(self):
    Thread.__init__(self)
    self.start()
  def run(self):
    ind=0
    chunks=""
    while(True):
      if shared.video==False:
        cv2.destroyAllWindows()
        break
      try:
        data=shared.sock.recv(1048576)
        chunks+=data
        print ("chunks:",len(''.join(chunks)))
        if len(''.join(chunks)) >= 921600:
          byte_frame = b''.join(chunks[0:921600])
          frame = np.frombuffer(byte_frame, dtype=np.uint8).reshape(480, 640, 3)
          gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
          cv2.imshow('frame',gray)
          cv2.waitKey(1)
          chunks=""
      except IndexError:
        pass

vid_receive()
vid_send()
