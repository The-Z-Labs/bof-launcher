# BOF Runner

A Rust-based command-line tool for executing BOF (Beacon Object Files) on Windows systems. This tool links into the libraries built by the `bof-launcher` repository.

## Overview

BOF Runner is a lightweight utility that loads and executes Beacon Object Files (BOFs) from disk. BOFs are small, position-independent code modules commonly used in red team operations and security research. This tool provides a simple interface to run BOF files directly from the command line. This example **DOES NOT** support arguments at this time.

## Features

- **Simple CLI Interface**: Easy-to-use command-line interface built with clap
- **Direct BOF Execution**: Load and execute BOF files from disk
- **Error Handling**: Comprehensive error reporting for file operations

## Prerequisites

- Windows 10/11 (x64)
- Rust toolchain (latest stable recommended)

## Installation
Build the `bof-launcher` libaries, and format the folder structure as depicted below.

### Project Structure
    ```
    bof_runner/
    ├── src/
    │   └── main.rs          # Main application logic
    ├── lib/                 # Static libraries, copy from zig-out/lib
    │   └── bof_launcher_win_x64.lib
    ├── Cargo.toml           # Rust project configuration
    └── README.md            # This file
    ```

### Building the Utility

1. Build the project:
   ```bash
   cargo build --release
   ```

2. The executable will be available at `target/release/bof_runner.exe`

## Usage
```bash
bof_runner.exe <bof-filename>
```