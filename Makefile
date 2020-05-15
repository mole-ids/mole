# ########################################################## #
# Makefile for Golang Project
# Includes cross-compiling, installation, cleanup
# ########################################################## #

# Check for required command tools to build or stop immediately
EXECUTABLES = git go find pwd
K := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH)))

ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

APPNAME=MoleIDS
BINARY=mole
BINDIR=build
VERSION=v0.0.0-dev
BUILD=`git rev-parse HEAD`
BUILDDATE=`date +%FT%T%z`
PACKAGE=github.com/mole-ids/mole/cmd

SRC=main.go
SRC_DEBUG=debug.go

# Setup linker flags option for build that interoperate with variable names in src code
LDFLAGS=-ldflags "-X ${PACKAGE}.AppName=${APPNAME} -X ${PACKAGE}.Version=${VERSION} -X ${PACKAGE}.BuildDate=${BUILDDATE} -X ${PACKAGE}.BuildHash=${BUILD}"

default: build

all: clean build_all install

build:
	go build ${LDFLAGS} -o ${BINDIR}/${BINARY} $(SRC)

debug:
	go build -tags=debug ${LDFLAGS} -o ${BINDIR}/${BINARY} $(SRC_DEBUG)

install:
	go install ${LDFLAGS}

test:
	go test -v -count=1 -cover ./...

docs:
	make -C ./docs docs

clean:
	rm -rf ${BINDIR}

.PHONY: check clean build debug install build_all all docs
