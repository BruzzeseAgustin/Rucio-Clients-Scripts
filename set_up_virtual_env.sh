#! /bin/bash

# FYI please adress to the following link if 
# you want to install further dependencies in jupyter.pic

apt install python3-pip

pip install virtualenv
python3 -m venv rucio
# virtualenv rucio

source rucio/bin/activate

git clone https://github.com/BruzzeseAgustin/Rucio-Clients-Scripts.git

pip install -r Rucio-Clients-Scripts/requirements.txt

pip install -Iv rucio-clients==1.23.11

cp Rucio-Clients-Scripts/rucio.cfg rucio/etc

export RUCIO_HOME=`pwd`/rucio/

