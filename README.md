# 3DES File Encryption Tool

This project provides a pure-Python implementation of the DES block cipher and builds a 3DES (EDE) cipher on top of it. A simple command-line interface allows encrypting and decrypting arbitrary files using CBC mode with PKCS#7 padding.

## Requirements

- Python 3.11 or later (standard library only)

## Running the CLI

```
python -m tdes.cli encrypt <input_file> <output_file> --key <hex_key> --iv <hex_iv>
python -m tdes.cli decrypt <input_file> <output_file> --key <hex_key> --iv <hex_iv>
```

Arguments:

- `--key`: 16-byte (K1=K2, K3 independent) or 24-byte key encoded as hexadecimal (spaces are ignored). When a 16-byte key is used it is expanded to 24 bytes internally as specified by the 3DES two-key variant.
- `--iv`: 8-byte initialization vector encoded as hexadecimal.

The tool reads and writes files in binary mode, so any file type can be processed. Padding is automatically added and removed using PKCS#7.

## Running the Tests

```
python -m unittest discover
```
