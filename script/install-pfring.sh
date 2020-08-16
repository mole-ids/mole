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

cwd=$(pwd)

cd /tmp

git clone https://github.com/ntop/PF_RING.git
cd PF_RING/kernel/
make && sudo make install

cd ../userland/lib
./configure --prefix=/usr/local/pfring && make && sudo make install

cd ../libpcap
./configure --prefix=/usr/local/pfring && make && sudo make install

sudo ldconfig
export CGO_LDFLAGS="-L/usr/local/pfring/lib/"
export CGO_CFLAGS="-I/usr/local/pfring/include/"

sudo modprobe pf_ring
echo pf_ring | sudo tee -a /etc/modules

cd "$pwd"
