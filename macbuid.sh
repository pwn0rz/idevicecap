#! /bin/bash

export CFLAGS=-I$(brew --prefix)/include LDFLAGS=-L$(brew --prefix)/lib
make