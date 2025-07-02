#!/bin/bash

apt update
apt install -y python3 python3-venv python3-dev gcc git-core sshfs curl
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

cd /opt

git clone https://github.com/kavat/anubi

cd /opt/anubi
python3 -m venv ./anubi_env
./anubi_env/bin/pip3 install -r pip_requirements.txt 

mkdir conf
mkdir conf/custom_rules
mkdir conf/custom_hash
mkdir conf/custom_ip
mkdir log
mkdir reports
mkdir stats".format(application_path),
