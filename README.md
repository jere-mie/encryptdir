# encryptdir

(pronounced encrypter)

A simple Python application to securely encrypt and decrypt specified files in specified directories.  
Created for assignment 1 of COMP-3750 at the University of Windsor, Winter 2023 by Jeremie Bornais and Ryan Prairie

## Requirements

- Golang version 1.20

## Set Up

The only required setup is to create a `config.yml` file. You can simply copy the sample config and edit as you like:

```bash
cp example_config.yml config.yml
```

Now you're ready to get encrypting!

## Running the Application

Simply run:

```bash
go run main.go
```

to run the application in encrypt mode. It will prompt you to enter a password. This password will be used to protect the RSA private key. If no RSA keys are found (according to the filepaths set by the config file), new ones will be generated using the password provided. 

### Decrypting

By default the program will encrypt files. However, to decrypt files instead, simply pass in the `-decrypt` flag, like so:

```bash
go run main.go -decrypt
```

## Command Line Options

- `-decrypt`: to run the application in decrypt mode (if you don't pass this value, the program will default to encrypting)
- `-password yourPasswordHere`: to put in a password. If you don't use do this, the app will prompt you for a password

## Testing the Application

To make testing the application easier, we've created some scripts and configurations so you can easily verify that encryptdir is working properly. Run the following to generate a new directory with a bunch of directories and files to use for testing:

```bash
sh scripts/create_test_files.sh
```

This will create the folder `testing_env` in the root of the project, with several folders and several files within those folders. **NOTE**: despite their file extensions, ALL of these files are simple plaintext files. They all contain a message similar to `hello from file.txt`. **NOTE**: there are some directories that were created by the script that do not appear in test_config.yml. **This was done on purpose** to allow users to verify that only the directories specified are encrypted/decrypted. The same is true for file extensions, not all file extensions in the test environment are encrypted, so you can verify that the configuration is actually being used.

Now, copy the `test_config.yml` to `config.yml` to set up the application for testing. This can be done via the following command:

```bash
cp test_config.yml config.yml
```

Now, simply run the application to encrypt all of the files!

```bash
# any password will do
go run main.go -password mypassword
```

Head over to `testing_env` to verify the proper files/directories were encrypted. Now, to test decryption, run the following:

```bash
# must be same password as before
go run main.go -decrypt -password mypassword
```

## Earthly Build

If you use [Earthly](https://earthly.dev/), you can use it to build our application in different ways:

### For Binary

`earthly +build`

### For Container:

`earthly +use-image`

### For Testing

`earthly +build-test`
