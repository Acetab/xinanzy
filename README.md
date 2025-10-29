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

### Quick start example

Below is a minimal end-to-end example that encrypts and decrypts a text file.

1. Prepare an example plaintext file (optional):

   ```bash
   echo "hello 3des" > plain.txt
   ```

2. Pick a key and IV, expressed as hexadecimal. The values below are 24-byte and 8-byte samples—feel free to substitute your own:

   - Key: `0123456789abcdeffedcba98765432100123456789abcdef`
   - IV:  `1234567890abcdef`

3. Encrypt the file (output is binary data):

   ```bash
   python -m tdes.cli encrypt plain.txt cipher.bin --key 0123456789abcdeffedcba98765432100123456789abcdef --iv 1234567890abcdef
   ```

4. Decrypt the ciphertext back to plaintext:

   ```bash
   python -m tdes.cli decrypt cipher.bin recovered.txt --key 0123456789abcdeffedcba98765432100123456789abcdef --iv 1234567890abcdef
   ```

5. Verify that the recovered content matches the original:

   ```bash
   cat recovered.txt
   # hello 3des
   ```

> 💡 使用中文步骤：首先准备明文文件，其次选好 16 或 24 字节的 16 进制密钥和 8 字节的 16 进制向量，然后按上面的 `encrypt` / `decrypt` 命令运行即可。

## Running the Tests

```
python -m unittest discover
```
