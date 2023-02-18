# getting the dependencies
deps:
    FROM golang:1.20

    # reuse this later
    ENV BIN_NAME encryptdir

    WORKDIR /app
    COPY go.mod go.sum .
    RUN go mod download

# builds the client binary
build-bin:
    FROM +deps

    COPY main.go .

    # copy cmd and whatever else in dir mode
    # this is like `cp -r`
    COPY --dir pkg/ cmd/ ./

    # build to file `imacry`
    RUN go build -race -o $BIN_NAME main.go

    SAVE ARTIFACT $BIN_NAME

# saves binary
build:
    FROM +build-bin
    # save file as artifact
    SAVE ARTIFACT $BIN_NAME AS LOCAL $BIN_NAME

build-image-base:
    FROM ubuntu:23.04

    COPY +build-bin/$BIN_NAME .

    COPY config.yml .

# puts you in interactive shell inside container,
# spits out image of that container
use-image:
    FROM +build-image-base

    # put you in interactive bash shell
    RUN --interactive bash

    SAVE IMAGE encryptdir-interactive:latest

test:
    FROM +build-image-base

    COPY ./scripts/create_test_files.sh .

    RUN ./create_test_files.sh

    RUN ./encryptdir -password="hi"

    RUN --interactive bash
