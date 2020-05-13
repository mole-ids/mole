#!/usr/bin/env bash

git clone https://github.com/ntop/PF_RING.git
cd PF_RING/kernel/
make && sudo make install
cd ../userland/lib
./configure --prefix=/usr/local/pfring && make && sudo make install
cd ../libpcap
./configure --prefix=/usr/local/pfring && make && sudo make install
cd ../tcpdump
./configure --prefix=/usr/local/pfring && make && sudo make install
sudo ldconfig
export CGO_LDFLAGS="-L/usr/local/pfring/lib/"
export CGO_CFLAGS="-I/usr/local/pfring/include/"

sudo modprobe pf_ring
echo pf_ring | sudo tee -a /etc/modules
