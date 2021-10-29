#!/bin/bash
if ! command -v pip &> /dev/null
then
  echo Installing pip...
  sudo apt install -y python3-pip
fi
sudo apt install -y python3-pyaudio
python3 -m pip install -r client/requirements.txt
