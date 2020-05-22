#!/usr/bin/env bash

# Copyright 2020 Jaume Martin

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# 	http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

sudo sh -c 'echo "/usr/local/lib" >> /etc/ld.so.conf'
sudo ldconfig

cd $cwd
