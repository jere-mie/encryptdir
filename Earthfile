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
    COPY --dir pkg/ ./

    # build to file `imacry`
    RUN go build -race -o $BIN_NAME main.go

# saves binary
build:
    FROM +build-bin
    # save file as artifact
    SAVE ARTIFACT $BIN_NAME AS LOCAL $BIN_NAME
