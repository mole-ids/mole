#!/usr/bin/env bash

YARA_VERSION="3.11.0"

wget "https://github.com/VirusTotal/yara/archive/v$YARA_VERSION.tar.gz" -O yara.tgz
tar xvfz yara.tgz
cd yara-$YARA_VERSION

./bootstrap.sh
./configure
make
sudo make install
