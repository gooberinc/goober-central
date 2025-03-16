# Server Setup

## Requirements
Before running the application, ensure that you have the following:

- Go 1.20 or higher
- Git

## Compilation Instructions

1. **Compile the application**
   Run this in your Terminal of choice.
   ```bash
   go build
   ```

3. **Run the compiled executable**
   After compilation, you can run it directly:
   ```bash
   ./goober-central
   ```
   Or if you're a Windows user:
   ```bash
   goober-central.exe
   ```
## Cross-Compilation

1. **Cross-Compilation**
    If you want to compile the application for a different operating system or architecture, use the `GOOS` and `GOARCH` environment variables.
    For example, to compile for Windows on a Linux machine:
   ```bash
   GOOS=windows GOARCH=amd64 go build -o goober-central.exe`
   ```
   
You're all set!
If you’d like to configure Telegram alongside Discord, refer to the instructions [here](https://github.com/WhatDidYouExpect/goober-central/blob/master/TELEGRAM.md).

Or if you'd like to compile it into an executable, refer to these instructions [here](https://https://github.com/WhatDidYouExpect/goober-central/blob/master/COMPILING.md)
