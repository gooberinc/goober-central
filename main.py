from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
import os
import json
from datetime import datetime
import requests
from typing import Optional
from pathlib import Path
import uuid
import requests
import json
import hashlib
import json
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threading import Thread
from fastapi import FastAPI
from datetime import datetime
from dotenv import load_dotenv


app = FastAPI()
origins = [
    "*"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# base dir
BASE_DIR = Path(__file__).resolve().parent

print(f"BASE_DIR: {BASE_DIR}")
load_dotenv()
app = FastAPI()

# path to bot.py and the stupid version file + tokens
BOT_FILE_PATH = os.path.join(BASE_DIR, 'static', 'goob', 'bot.py')
LATEST_VERSION_PATH = os.path.join(BASE_DIR, 'static', 'latest_version.json')
TOKENS_FILE_PATH = os.path.join(BASE_DIR, "tokens.json")


# stupid ass hash thing i regret making this
def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def update_version_file(file_hash):
    if os.path.exists(LATEST_VERSION_PATH):
        with open(LATEST_VERSION_PATH, "r") as version_file:
            current_data = json.load(version_file)
    else:
        current_data = {}
    current_data["hash"] = file_hash
    current_data["last_modified"] = datetime.utcnow().isoformat()
    with open(LATEST_VERSION_PATH, "w") as version_file:
        json.dump(current_data, version_file, indent=4)

def load_tokens():
    if os.path.exists(TOKENS_FILE_PATH):
        with open(TOKENS_FILE_PATH, "r") as file:
            return json.load(file)
    return {}

# Function to save the tokens to the file
def save_tokens(tokens):
    with open(TOKENS_FILE_PATH, "w") as file:
        json.dump(tokens, file, indent=4)


# this basically watches bot.py for changes and updates the hash automatically
class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == BOT_FILE_PATH:
            print(f"\033[38;5;46mINFO\033[0m:     {BOT_FILE_PATH} has been modified, updating hash...")
            file_hash = calculate_file_hash(BOT_FILE_PATH)
            update_version_file(file_hash)
            print(f"\033[38;5;46mINFO\033[0m:     Updated hash: {file_hash}")

# initalizes the watchdog for the above class
def start_watchdog():
    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, os.path.dirname(BOT_FILE_PATH), recursive=False)
    observer.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# twas events but now i need lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("app is starting up...")
    watchdog_thread = Thread(target=start_watchdog, daemon=True)
    watchdog_thread.start()
    print("watchdog started and running in the background")
    yield
    print("goodbye")

app = FastAPI(lifespan=lifespan)

# log recieved pings
LOG_FILE = os.path.join(BASE_DIR, "server_log.json")
# i dont know why i defined it here
templates = Jinja2Templates(directory=BASE_DIR / "templates")
DISCORD_WEBHOOK_URL = os.getenv("webhookID")
TELEGRAM_BOT_TOKEN = os.getenv("telegram_token")
TELEGRAM_CHAT_ID = os.getenv("telegram_id")
TELEGRAM_ENABLED = os.getenv("use_telegram")

# i need to update some of this shit man
def ensure_log_file():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
    if not os.path.exists(TOKENS_FILE_PATH):
        with open(TOKENS_FILE_PATH, "w") as f:
            json.dump([], f)

# send the incoming request to discord when the server gets pinged
def send_discord_message(data):
    # get version from json file
    try:
        with open("static/latest_version.json", "r") as version_file:
            latest_version_data = json.load(version_file)
            latest_version = latest_version_data.get("version", "0.0.0")
    except Exception as e:
        print(f"Failed to load version data: {str(e)}")
        latest_version = "0.0.0"  # fallback

    # get version data from incoming data
    version = data.get("version", "Unknown")
    name = data.get("name", "Unknown")
    
    # stupid ass check to see if its a valid version
    version_display = version
    if version != "Unknown" and version > latest_version: 
        version_display = f"{version} (invalid)" # this doesnt work if the version is lower since it only applys it to higher versions

    # prep discord embed
    embed = {
        "title": "Bot Activated",
        "description": f"",
        "color": 5814783,  # light blue
        "fields": [
            {
                "name": "Name",
                "value": data.get("name", "Unknown"),
                "inline": True
            },
            {
                "name": "Timestamp",
                "value": data.get("timestamp", "Unknown"),
                "inline": True
            },
            {
                "name": "Version",
                "value": version_display,
                "inline": True
            },
            {
                "name": "Slash Commands",
                "value": data.get("slash_commands", "False"),
                "inline": True
            },
            {
                "name": "Memory File Info",
                "value": f"File size: {data.get('memory_file_info', {}).get('file_size_bytes', 'Unknown')} bytes\nLine count: {data.get('memory_file_info', {}).get('line_count', 'Unknown')}",
                "inline": False
            }
        ],
        "footer": {
            "text": "Bot Activity Log"
        }
    }

    # send payload
    payload = {
        "embeds": [embed]
    }
    
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload)
    except Exception as e:
        print(f"Failed to send message to Discord: {str(e)}")

def send_telegram_message(data):
    if TELEGRAM_ENABLED == None:
        return
    # get version from json file
    try:
        with open("static/latest_version.json", "r") as version_file:
            latest_version_data = json.load(version_file)
            latest_version = latest_version_data.get("version", "0.0.0")
    except Exception as e:
        print(f"Failed to load version data: {str(e)}")
        latest_version = "0.0.0"  # fallback

    # get version data from incoming data
    version = data.get("version", "Unknown")
    name = data.get("name", "Unknown")

    # version check
    version_display = version
    if version != "Unknown" and version > latest_version: 
        version_display = f"{version} (invalid)" 

    message = (
        f"Name: {name}\n"
        f"Timestamp: {data.get('timestamp', 'Unknown')}\n"
        f"Version: {version_display}\n"
        f"Slash Commands: {data.get('slash_commands', 'False')}\n"
        f"Memory File Info:\n"
        f"   ├ File Size: {data.get('memory_file_info', {}).get('file_size_bytes', 'Unknown')} bytes\n"
        f"   └ Line Count: {data.get('memory_file_info', {}).get('line_count', 'Unknown')}\n"
    )

    # send the message to Telegram
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message
    }

    try:
        print("tried")
        reponse = requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage", json=payload)
        print(reponse.text)
    except Exception as e:
        print(f"Failed to send message to Telegram: {str(e)}")

# A list of files or directories to disallow
DISALLOWED_FILES = ["main.py", "README.md"]  # add any files you want to block

@app.post("/check-if-available")
async def check_if_available(request: Request):
    try:
        # Read the raw body and print it for debugging
        body = await request.body()
        print("Raw Request Body:", body.decode())

        if not body:
            raise HTTPException(status_code=400, detail="Empty request body")

        # Attempt to parse the JSON body
        try:
            data = await request.json()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid JSON format")

        name = data.get("name")
        if not name:
            raise HTTPException(status_code=400, detail="Name is required")

        # Load existing tokens
        tokens = load_tokens()

        # Check if the name is already taken
        if name in tokens:
            return JSONResponse(content={"available": False, "message": "Name already taken"})

        return JSONResponse(content={"available": True})

    except Exception as e:
        print(f"Error in /check-if-available: {str(e)}")
        return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})

# route for name registration
@app.post("/register")
async def register_name(request: Request):
    try:
        data = await request.json()
        name = data.get("name").strip() if data.get("name") else None
        
        if not name:
            raise HTTPException(status_code=400, detail="Name is required")
        
        # generate token for name
        token = str(uuid.uuid4()) # using v4 for different strings each time

        # load existing
        tokens = load_tokens()

        # check if its already been registered
        if name in tokens:
            raise HTTPException(status_code=400, detail="Name already registered")
        
        # store the name n shit in the file
        tokens[name] = token
        save_tokens(tokens)
        
        return JSONResponse(content={"message": "Name registered successfully", "token": token})

    except Exception as e:
        print(f"Error in /register: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# modified to check if the token + name pair is valid
@app.post("/ping")
async def receive_ping(request: Request):
    try:
        data = await request.json()
        if not data:
            raise HTTPException(status_code=400, detail="Invalid or missing JSON payload")

        name = data.get("name")
        token = data.get("token")
        print(name, token)
        if not name or not token:
            raise HTTPException(status_code=400, detail="Name and token are required")

        tokens = load_tokens()

        if name not in tokens or tokens[name] != token:
            raise HTTPException(status_code=403, detail="Invalid name or token. Please register again.")
        
        data["timestamp"] = datetime.utcnow().isoformat()

        with open(LOG_FILE, "r+") as f:
            logs = json.load(f)
            logs.insert(0, data)
            f.seek(0)
            json.dump(logs, f, indent=4)

        send_discord_message(data)
        send_telegram_message(data)

        return JSONResponse(content={"message": "Ping received successfully", "timestamp": data["timestamp"]})

    except Exception as e:
        print(f"Error in /ping: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def home(request: Request):
    # print full template path cause at one point it kept shitting out
    template_path = os.path.join(BASE_DIR, "templates", "main.html")
    print(f"Looking for template at: {template_path}")
    
    return templates.TemplateResponse("main.html", {"request": request})


@app.get("/{file_path:path}")
async def serve_json_file(file_path: str):
    # serve files from static dir
    file_full_path = os.path.join(BASE_DIR, "static", file_path)

    if os.path.exists(file_full_path) and os.path.isfile(file_full_path):
        # give json files with the correct french MIME type
        if file_path.endswith(".json"):
            return FileResponse(file_full_path, media_type="application/json")
        else:
            # if its not json just give it
            return FileResponse(file_full_path)
    else:
        raise HTTPException(status_code=404, detail="File not found")


# make sure the log file exists
ensure_log_file()
