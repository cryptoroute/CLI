# C++ Command Line Toolkit

A powerful, modular, and extensible command-line utility written in modern C++.  
Includes file operations, AES encryption, XOR cipher, hashing, multi-threaded directory scanning, plugin system, DLL injection, JSON config handling, and logging.

---

## Features

- XOR & AES File Encryption/Decryption
- Key Generator
- List & Scan Directories (multi-threaded)
- SHA-256 Hashing
- Plugin System (load `.dll` or `.so` at runtime)
- DLL Injection (Windows only)
- JSON Configuration Loader
- Logger with timestamped output
- File Comparison (diff)

---

## Requirements

### Libraries
- C++17
- OpenSSL
- [nlohmann/json.hpp](https://github.com/nlohmann/json)
- POSIX or Windows (cross-platform support)

---

## Build Instructions

### Linux / Termux / macOS:
```bash
clang++ main.cpp -o tool -std=c++17 -lssl -lcrypto -ldl -pthread
