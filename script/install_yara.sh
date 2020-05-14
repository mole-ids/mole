#!/usr/bin/env bash

YARA_VERSION="3.11.0"

cwd=$(pwd)
cd /tmp

wget "https://github.com/VirusTotal/yara/archive/v$YARA_VERSION.tar.gz" -O yara.tgz
tar xvfz yara.tgz
cd yara-$YARA_VERSION

./bootstrap.sh
./configure --enable-magic --with-crypto
make
sudo make install

cd $cwd
