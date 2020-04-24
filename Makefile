# ########################################################## #
# Makefile for Golang Project
# Includes cross-compiling, installation, cleanup
# ########################################################## #

# Check for required command tools to build or stop immediately
EXECUTABLES = git go find pwd
K := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH)))

ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

APPNAME=Mole
BINARY=mole
BINDIR=build
VERSION=1.0.0
BUILD=`git rev-parse HEAD`
BUILDDATE=`date +%FT%T%z`

PLATFORMS=darwin linux windows
ARCHITECTURES=386 amd64

# Setup linker flags option for build that interoperate with variable names in src code
LDFLAGS=-ldflags "-X main.AppName=${APPNAME} -X main.Version=${VERSION} -X main.BuildDate=${BUILDDATE} -X main.BuildHash=${BUILD}"

default: build

all: clean build_all install

build:
	go build ${LDFLAGS} -o ${BINDIR}/${BINARY}

debug:
	go build -tags=debug ${LDFLAGS} -o ${BINDIR}/${BINARY}

build_all:
	$(foreach GOOS, $(PLATFORMS),\
	$(foreach GOARCH, $(ARCHITECTURES), $(shell export GOOS=$(GOOS); export GOARCH=$(GOARCH); go build -v -o $(BINDIR)/$(BINARY)-$(GOOS)-$(GOARCH))))

install:
	go install ${LDFLAGS}

test:
	go test -v -count=1 -cover ./...
	
clean:
	rm -rf ${BINDIR}

.PHONY: check clean build debug install build_all all
