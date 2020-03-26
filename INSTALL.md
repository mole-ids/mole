

Tested using Ubuntu 18.04.4 LTS


Install build tools
===================

```
sudo apt install build-essential autoconf libtool bison flex 
```

Install recent go
=================

```
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt update
sudo apt install golang-go
```

Install PF_RING
===============

```
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
echo 'export CGO_LDFLAGS="-L/usr/local/pfring/lib/"' >> $HOME/.bash_profile
echo 'export CGO_CFLAGS="-I/usr/local/pfring/include/"' >> $HOME/.bash_profile
source $HOME/.bash_profile
```

Load PD_RING
============

```
modprobe pf_ring
```

Install Yara
============

```
wget https://github.com/VirusTotal/yara/archive/v3.11.0.tar.gz -O yara.tgz
tar xvfz yara.tgz
cd yara-3.11.0
./bootstrap.sh
./configure
make
sudo make install
```

Install Go dependencies
=======================

```
go get github.com/hillu/go-yara
go get github.com/google/gopacket/pfring
```

Build 
=====

```
go build main.go
```
