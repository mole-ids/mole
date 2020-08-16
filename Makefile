# ########################################################## #
# Makefile for Golang Project
# Includes cross-compiling, installation, cleanup
# ########################################################## #

ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

APPNAME=MoleIDS
BINDIR=build
VERSION=`git describe --abbrev=0`
BUILD=`git rev-parse HEAD`
BUILDDATE=`date +%FT%T%z`
PACKAGE=github.com/mole-ids/mole/cmd
COVER_PROFILE=c.out

SRC=main.go

# Setup linker flags option for build that interoperate with variable names in src code
EXTLDFLAGS=-extldflags '-static'
LDFLAGS=-ldflags "-w -s -X ${PACKAGE}.AppName=${APPNAME} -X ${PACKAGE}.Version=${VERSION} -X ${PACKAGE}.BuildDate=${BUILDDATE} -X ${PACKAGE}.BuildHash=${BUILD}"

default: build

all: clean build

build-linux: build-linux64 build-linux32

build-linux64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -race ${LDFLAGS} -o ${BINDIR}/mole_linux_amd64 $(SRC)

build-linux32:
	GOOS=linux GOARCH=386 CGO_ENABLED=1 go build ${LDFLAGS} -o ${BINDIR}/mole_linux_386 $(SRC)

build-macos:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -race ${LDFLAGS} -o ${BINDIR}/mole_darwin_amd64 $(SRC)

build-pfring: build-pfring-linux64 build-pfring-linux32

build-pfring-linux64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -tags "pf_ring" -race ${LDFLAGS} -o ${BINDIR}/mole_linux_amd64_pfring $(SRC)

build-pfring-linux32:
	GOOS=linux GOARCH=386 CGO_ENABLED=1 go build -tags "pf_ring" ${LDFLAGS} -o ${BINDIR}/mole_linux_386_pfring $(SRC)

test:
	go test -v -count=1 ./...

test-race:
	go test -race -v -count=1 ./...

test-cover:
	go test -v -count=1 -cover -coverprofile=${COVER_PROFILE} ./...

docs:
	make -C ./docs docs

clean:
	rm -rf ${BINDIR}

.PHONY: check clean build-linux build-linux64 build-linux32 build-pfring-linux64 build-pfring-linux32 build-macos build-pfring test test-race test-cover all docs
