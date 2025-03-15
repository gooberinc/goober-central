# Server Setup

## Requirements
Before running the application, ensure that you have the following:

- Python 3.7 or higher
- pip (Python package installer)
- Uvicorn for running the server

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
    Install the required dependencies from requirements.txt:
   `pip install -r requirements.txt`

4. **Run the script**:
    Start the application using uvicorn:
   ``uvicorn main:app --host {host} --port {port}``
   Replace `{host}` with your desired host (e.g., `0.0.0.0` for listening on all interfaces) and `{port}` with the desired port number.

5. **Open it in a web browser**:
    Once the server is running, open your browser of choice and navigate to `http://{host}:{port}` (e.g., `http://localhost:8000`)

6. **Configure goober**:
    Once you've confirmed that the server is running, navigate to your existing goober install. Inside `config.py`, update the `VERSION_URL` variable to point to the domain where goober central is hosted.

You're all set!
If you’d like to configure Telegram alongside Discord, refer to the instructions [here](https://github.com/WhatDidYouExpect/goober-central/blob/master/TELEGRAM.md).
