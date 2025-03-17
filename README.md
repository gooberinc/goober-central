# Server Setup

## Requirements
Before running the application, ensure that you have the following:

- Go 1.20 or higher
- Git

## Setup Instructions

1. **Clone the Repository**:
   If you haven't already, clone the repository to your local machine:
   ```bash
   git clone <repository-url>
   cd <repository-directory>

2. **Create a `.env` file**:
    In the project root directory, create a .env file and add the following line:
    `webhookID={discord webhook}`

3. **Install Dependencies**:
    Install the required dependencies from go.mod
   ```bash
   go mod tidy
   ```

5. **Run the script**:
    Start the application using go:
   ```bash
   go run main.go
   ```

> [!TIP]
> If you're looking to boost its speed even slightly, try compiling it!

5. **Open it in a web browser**:
    Once the server is running, open your browser of choice and navigate to `http://localhost:9094`

6. **Configure goober**:
    Once you've confirmed that the server is running, navigate to your existing goober install. Inside `config.py`, update the `VERSION_URL` variable to point to the domain where goober central is hosted.

> [!IMPORTANT]  
> Once you self-host goober central, version checking and name registration become your responsibility! Not mine!

You're all set!
If you’d like to configure Telegram alongside Discord, refer to the instructions [here](https://github.com/WhatDidYouExpect/goober-central/blob/master/TELEGRAM.md).

Or if you'd like to compile it into an executable, refer to these instructions [here](https://github.com/WhatDidYouExpect/goober-central/blob/master/COMPILING.md)
