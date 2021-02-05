#! /bin/bash

apt install python3-pip

pip install virtualenv
virtualenv rucio
source rucio/bin/activate

git clone https://github.com/BruzzeseAgustin/Rucio-Clients-Scripts.git

pip install -r Rucio-Clients-Scripts/requirements.txt
cp Rucio-Clients-Scripts/rucio.cfg rucio/etc

export RUCIO_HOME=`pwd`/rucio/
