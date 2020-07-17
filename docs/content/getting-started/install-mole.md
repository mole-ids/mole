# Install Mole

Getting Mole IDS From The Soruce
{: .subtitle }

At the moment Mole IDS is tested under Ubuntu and Debian as Mole IDS is programed in [Golang](https://golang.org/) we suspect you can build Mole almost on any Linux box. However, the Mole IDS team is working to port Mole to the major platforms.

!!! note "Mole IDS Dependencies & Requirements"
    Mole IDS is build upon two libraries and they have to be installed on the system you want to run Mole IDS. 

    * [Yara](https://virustotal.github.io/yara/)
    * [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/)


Down below is the whole intallation process so please follow up the process and everything will be fine.

## Pre-requisites

The following packages are needed to compile Yara and PF_RING.

```shell
sudo apt install build-essential \
                 pkg-config \
                 autoconf \
                 automake \
                 libtool \
                 bison \
                 flex \
                 make \
                 gcc \
                 libjansson-dev \
                 libmagic-dev
```

### Install Golang

??? example "Install Golang from package repository"
   ```shell tab="Ubuntu"
    sudo add-apt-repository ppa:longsleep/golang-backports
    sudo apt update
    sudo apt install golang-go
   ```

   ```shell tab="Debian"
    sudo apt update
    sudo apt install golang-go
   ```


??? tldr "Install Golang manually"
    Golang can be downlaoded from [https://golang.org/dl/](https://golang.org/dl/) and configure it following the steps in [https://golang.org/doc/install](https://golang.org/doc/install).

    To compile Mole IDS you only need to define the `GOPATH` and `GOBIN` environment variables according to your needs.


### Install PF_RING

PF_RING has 4 parts that need to be compiled and installed separately.

```shell
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

#### Load PF_RING

```shell
sudo modprobe pf_ring
echo pf_ring | sudo tee -a /etc/modules
```

### Install Yara

At the moment Mole IDS uses Yara version 3.11.0. We know there is a newer version of Yara and we will added asoon as possible.

```shell
wget https://github.com/VirusTotal/yara/archive/v3.11.0.tar.gz -O yara.tgz
tar xvfz yara.tgz
cd yara-3.11.0
./bootstrap.sh
./configure --enable-magic
make
sudo make install
```

## Install

First of all you need to clone or download Mode IDS project from [Github](https://github.com/mole-ids/mole).

Once you have the source code it should be placed at `$GOPATH/src/github.com/mole-ids/mole`, that way everything will work as expected.

Mole IDS can be installed under `%GOBIN%` by using the Golang installer feature. We wrapped that command behind the following command.

```shell
make install
```

### Build

On the other hand, you can build Mole for your platform by using the `build` make command. This command will leave the Mole IDS executable under `<project_path>/build/`.

```shell
make build
```
