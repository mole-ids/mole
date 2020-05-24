# Install Mole


## Install

```sh
make install
```

## Development

### Install build tools

```sh
sudo apt install build-essential autoconf libtool bison flex make
```

### Install recent go

#### Ubuntu

```sh
sudo add-apt-repository ppa:longsleep/golang-backports
sudo apt update
sudo apt install golang-go
```

#### Debian

```sh
sudo apt update
sudo apt install golang-go
```

#### Manually
Follow the process from https://golang.org/dl

### Install PF_RING

```sh
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

### Load PF_RING

```sh
sudo modprobe pf_ring
echo pf_ring | sudo tee -a /etc/modules
```

### Install Yara

```sh
wget https://codeload.github.com/VirusTotal/yara/tar.gz/v4.0.0 -O yara.tgz
tar xvfz yara.tgz
cd yara-4.0.0
./bootstrap.sh
./configure
make
sudo make install
```

### Build

To build Mole for your platform use the `build` make command

```sh
make build
```

or if you want to build for the major platforms use the followinf command.

```sh
make build_all
```