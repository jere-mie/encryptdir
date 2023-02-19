# Architecture

**This document describes the high-level architecture of this project**

If you want to familiarize yourself with the code base and _generally_ how it works, this is a good place to be.

## Overview

This is a file encrypter that operates concurrently and can walk directories.
It has two states: `Init` and `Operation`.
It uses some central structures, including an RSA key pair and a key map, which is a map of file extensions to AES keys.

### Init

The first state is `Init`.
The encrypter starts by:

1. Reading in the config file.

2. Loading in AES keys, which are encrypted and signed by the RSA keys.
   Before encryption, the key map is serialized to JSON.

3. If the AES keys or the key map don't exist, they are generated.

4. Loading in the RSA keys from an AES encrypted x509 PEM key.
   If the RSA keys don't exist, they are generated.

### Operation

The `Operation` state has two modes: encryption and decryption.
Both modes run concurrently.
To understand the architectural decisions, it is important to understand the problems that arise when running a concurrent encrypter on different directories at once.

To solve the problem of potentially getting the same file twice, we use a solution that involves "coloring" nodes in a graph.
In encryption mode:

1. If a node is colored, it is skipped.
2. If a node is not colored, it is colored.

In decryption mode:

1. If a node is colored, it is uncolored.
2. If a node is not colored, it is skipped.

To mark files in a way that is low collision and easily verifiable, we mark them with the RSA keys signed AES key.
This method is low collision and easy to verify.

To solve the issue of multiple files being opened at the same time, we create a second file.
This process is done atomically because the OS guarantees the syscall.
The plain text file is transferred to a cipher text file while encrypting, and then the cipher text file is renamed to the plain text file name.
This ensures that if the other file exists, someone else has been working on it.

## Code Map

#### Code Map Legend

`<file name>` for a file name

`<folder name>/` for a folder

`<folder name>/<file name>` for a file within a folder

### `Earthfile`

Build system using containers.
Lets us generate a test environment thats interactable and containerized with one command.

### `scripts/`

Scripts to do shortcuts like creating test files,
encryption, and decryption.

### `main.go`

Program entry point.

### `pkg/`

Vast majority of codebase.

### `pkg/encryptdir/`

Heart of this program.
Holds most of the business logic.

### `pkg/rsa/`

Code for RSA stuff.

### `pkg/aes/`

AES stuff.

### `pkg/config/`

Config stuff.

### `cmd`

CLI logic.
