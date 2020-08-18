# Compiling Mole IDS

Mole IDS can be compiled for the three major operating systmes easily. We have
wirte a Dockerfile that generates an image that helps to build Mole IDS. That
image generates static binaries except for Windows, although it is compiled
statically.

In contrast you can build Mole IDS for your system without using the docker image.
But in that case you will have to install some dependencies and you will have the
change to build Mole IDS either dynamically or statically.

!!! note "Mole IDS Dependencies & Requirements"
    Mole IDS is build upon two libraries and they have to be installed on the
    system you want to run Mole IDS.

    * [Yara](https://virustotal.github.io/yara/)
    * [PF_RING](https://www.ntop.org/products/packet-capture/pf_ring/)

You can build Mole IDS for Windows and Linux from a Linux box and for MacOS X from
a Mac machine.

Down below is the whole intallation process so please follow up the process and
everything will be fine.

## Pre-requisites

The following packages are needed to compile Yara and PF_RING.

??? example "Install build dependencies"

    ```shell tab="Debian/Ubuntu"
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

    ```shell tab="MacOS X"
    brew install autoconf automake libtool make pkg-config git
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

    ```shell tab="MacOS X"
    brew install golang
    ```

??? tldr "Install Golang manually"
    Golang can be downlaoded from [https://golang.org/dl/](https://golang.org/dl/)
    and configure it following the steps in [https://golang.org/doc/install](https://golang.org/doc/install).

    To compile Mole IDS you only need to define the `GOPATH` and `GOBIN`
    environment variables according to your needs.

### Install PF_RING

PF_RING has 3 parts that need to be compiled and installed separately.

!!! note About PF_Ring
    PF_Ring is only avaliable for Linux

```shell
tmp=$(mktemp -d -t pf_ring-XXXXXX)
git clone https://github.com/ntop/PF_RING.git ${tmp}

cd ${tmp}/kernel/
make && sudo make install

cd ../userland/lib
./configure --prefix=/usr/local/pfring && make && sudo make install

cd ../libpcap
./configure --prefix=/usr/local/pfring && make && sudo make install

sudo ldconfig
echo 'export CGO_LDFLAGS="-L/usr/local/pfring/lib/"' >> $HOME/.bash_profile
echo 'export CGO_CFLAGS="-I/usr/local/pfring/include/"' >> $HOME/.bash_profile
source $HOME/.bash_profile
```

#### Load PF_RING

!!! note About PF_Ring
    PF_Ring is only avaliable for Linux

```shell
sudo modprobe pf_ring
echo pf_ring | sudo tee -a /etc/modules
```

### Install Yara

Mole IDS uses the latest Yara version avaliable at the moment, which is Yara v4.0.2.

```shell
wget https://github.com/VirusTotal/yara/archive/4.0.2.tar.gz -O yara.tgz
tar xvfz yara.tgz
cd yara-4.0.2
./bootstrap.sh
./configure
make
sudo make install
```

## Install

First of all you need to clone or download ModeIDS project from [Github](https://github.com/mole-ids/mole).

Once you have the source code it should be placed at
`$GOPATH/src/github.com/mole-ids/mole`, that way everything will work as expected.

Mole IDS can be installed under `%GOBIN%` by using the Golang installer feature.
We wrapped that command behind the following command.

```shell
make install
```

### Build

On the other hand, you can build Mole for your platform by using the `build`
make command. This command will leave the Mole IDS executable under `<project_path>/build/`.

```shell
make build-linux # Will compile build-linux64 and build-linux32
make build-linux64
make build-linux32
make build-macos
make build-pfring # Will compile build-pfring-linux64 and build-pfring-linux32
make build-pfring-linux64
make build-pfring-linux32
```

!!! note
    Those make commands may fail as they are not used for building Mole IDS, but
    there is no reason because they should fail either.
