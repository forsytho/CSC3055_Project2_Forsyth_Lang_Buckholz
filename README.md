# CSC3055_Project2_Forsyth_Lang_Buckholz
Contributors: Owen Forsyth, Andrew Buckholz, Ayden Lang

## Overview
This project implements a secure secrets vault in Java. It allows you to store and retrieve encrypted passwords and private keys. The vault uses AES-GCM with and without Additional Authenticated Data for encryption, and scrypt for key derivation.

## Vault Features
- **Add a new service, username, and password triple**
- **Lookup a username–password pair for a given website**
- **Add a new service and username with a randomly generated password**
- **Add a new service and private key pair**
- **Lookup an ElGamal private key**
- **Generate a 512-bit ElGamal key pair** (public key output to user as Base64)

## Project Structure
- **Main.java** - Entry point of application
- **CLIHandler.java** - Handles command line interaction
- **Vault.java** - Core class that creates/loads the vault and manages secrets 
- **VaultData.java** - In-memory data structure for the vault 
- **VaultKey.java** - Holds the encrypted vault key and its IV 
- **VaultEntry.java** - Abstract base class for vault entries 
- **PasswordEntry.java** - Extends VaultEntry for password entries 
- **PrivateKeyEntry.java** - Extends VaultEntry for private key entries
- **CryptoUtils.java** - Contains methods for encryption, decryption, and random password generation
- **JsonHandler.java** - Handles JSON serialization/deserialization of vault data

- ## Required .jar files
  
- merrimack.util        <-- gitignored for professor's convenience
- jackson-score-2.18.2.jar
- jackson-databind-2.18.2.jar
- jackson-annotations-2.18.2.jar
- bcprov-jdk18on-1.80.jar

## Usage
- First the user will be prompted for a password. This password will be used to create a new vault with a key dependent on the password
- Note: In the future, the user will be able to access the vault and its secrets with the knowledge of this password

- Command Line Interface will give 7 options to the user
  
  1. Add Password Entry
  2. Lookup Password
  3. Add Random Password Entry
  4. Add Private Key Entry
  5. Lookup ElGamal Private Key
  6. Add Generated ElGamal Key Pair
  7. Exit

 - User inputs a digit 1-7 and the CLI proceeds with the respective method
 - CLI loop only stops when user exits, which first encrypts and saves the on-memory vault data to vault.json


## Build and Run Instructions

### Using Command Line

1. MacOS
  Navigate to project folder
  Compile with : javac -d bin -cp "lib/*" $(find src/main -name "*.java")
  Run with : java -cp "bin:lib/*" Main

2. Windows
   Navigate to project folder
   Compile with : javac -d bin -cp ".;lib/*" src\main\*.java
   Run with: java -cp "bin;lib/*" Main
