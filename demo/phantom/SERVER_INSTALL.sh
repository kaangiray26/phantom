#!/bin/bash
sudo apt install -y mariadb-server
sudo systemctl start mariadb.service
sudo systemctl enable mariadb.service
echo Enter new password for the database:
read varname

sudo mysql_secure_installation <<EOF

Y
$varname
$varname
Y
Y
Y
Y
EOF

sudo mariadb <<EOF

update mysql.user set plugin='' where user='root';
flush privileges;
CREATE DATABASE phantom;
USE phantom;
CREATE TABLE IF NOT EXISTS userlist (username VARCHAR(256), hash VARCHAR(256), salt VARCHAR(256));
CREATE TABLE IF NOT EXISTS iplist (username VARCHAR(256), addr VARCHAR(100), status VARCHAR(10), last_seen DATETIME);
exit
EOF

echo "credentials={'user':'root','password':'${varname}'}" >> server/db_config.py

if ! command -v pip &> /dev/null
then
  echo Installing pip...
  sudo apt install -y python3-pip
fi

python3 -m pip install -r server/requirements.txt

if ! command -v ifconfig &> /dev/null
then
  echo Installing net-tools...
  sudo apt install -y net-tools
fi

if ! command -v curl &> /dev/null
then
  echo Installing curl...
  sudo apt install -y curl
fi

echo INSTALLATION DONE.
exit