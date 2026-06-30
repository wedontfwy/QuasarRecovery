# QuasarRecovery

QuasarRecovery is a read-only configuration recovery tool for built Quasar client binaries.

It parses a .NET executable with dnlib, locates the obfuscated Quasar `Settings` class, extracts encrypted configuration fields, and decrypts them using Quasar’s AES-256 configuration encryption format.



## Demonstration

[▶ Watch Demo](https://www.youtube.com/watch?v=4IlYxHCPQPU)




## Screenshot



<img width="1298" height="916" alt="image" src="https://github.com/user-attachments/assets/8c0bfa47-62c9-455c-a35c-f3cfc1365fc3" />



## Features

- Read-only static analysis
- Does not execute the selected binary
- Supports obfuscated Quasar client builds
- Extracts raw encrypted config values
- Decrypts Quasar AES-256 protected settings
- Recovers hosts/IP and port
- Recovers version, tag, mutex, install name, startup key, and log directory
- Detects embedded server certificate field
- Exports recovered results as JSON

## Recovered Fields

- Hosts / C2 address
- Version
- Reconnect delay
- Install directory
- Install filename
- Mutex
- Startup key
- Tag
- Log directory name
- Install enabled
- Startup enabled
- Logger enabled
- Hide file
- Hide log directory
- Hide install subdirectory
- Unattended mode
- Encryption key
- Server signature, raw/encrypted
- Server certificate, raw/encrypted

## How It Works

Quasar stores most client configuration values as encrypted Base64 strings.  
QuasarRecovery finds the encrypted values inside the binary, identifies the SHA1-like encryption key, then uses the same AES-256 + HMAC-SHA256 format used by Quasar to decrypt the configuration.

Encrypted format:

```text
[ HMAC-SHA256 | IV | AES-CBC ciphertext ]
