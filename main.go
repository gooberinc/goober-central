package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

var (
	BASE_DIR            string
	BOT_FILE_PATH       string
	LATEST_VERSION_PATH string
	TOKENS_FILE_PATH    string
	LOG_FILE            string
	DISCORD_WEBHOOK_URL string
	TELEGRAM_BOT_TOKEN  string
	TELEGRAM_CHAT_ID    string
	TELEGRAM_ENABLED    string
	BuildDate           string
	BuildBranch         string
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	BASE_DIR, _ = os.Getwd()
	BOT_FILE_PATH = filepath.Join(BASE_DIR, "static", "goob", "bot.py")
	LATEST_VERSION_PATH = filepath.Join(BASE_DIR, "static", "latest_version.json")
	TOKENS_FILE_PATH = filepath.Join(BASE_DIR, "tokens.json")
	LOG_FILE = filepath.Join(BASE_DIR, "server_log.json")

	DISCORD_WEBHOOK_URL = os.Getenv("webhookID")
	TELEGRAM_BOT_TOKEN = os.Getenv("telegram_token")
	TELEGRAM_CHAT_ID = os.Getenv("telegram_id")
	TELEGRAM_ENABLED = os.Getenv("use_telegram")
}

func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func updateVersionFile(fileHash string) error {
	var currentData map[string]interface{}
	if _, err := os.Stat(LATEST_VERSION_PATH); err == nil {
		file, err := ioutil.ReadFile(LATEST_VERSION_PATH)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(file, &currentData); err != nil {
			return err
		}
	} else {
		currentData = make(map[string]interface{})
	}

	currentData["hash"] = fileHash
	currentData["last_modified"] = time.Now().UTC().Format(time.RFC3339)

	file, err := json.MarshalIndent(currentData, "", "    ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(LATEST_VERSION_PATH, file, 0644)
}

func loadTokens() (map[string]string, error) {
	if _, err := os.Stat(TOKENS_FILE_PATH); err == nil {
		file, err := ioutil.ReadFile(TOKENS_FILE_PATH)
		if err != nil {
			return nil, err
		}
		var tokens map[string]string
		if err := json.Unmarshal(file, &tokens); err != nil {
			return nil, err
		}
		return tokens, nil
	}
	return make(map[string]string), nil
}

func saveTokens(tokens map[string]string) error {
	file, err := json.MarshalIndent(tokens, "", "    ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(TOKENS_FILE_PATH, file, 0644)
}

func sendUpdateNotification(fileHash string) {
	message := fmt.Sprintf("Detected Change!\nNew Hash: %s", fileHash)
	embed := map[string]interface{}{
		"title":       "File Updated",
		"description": message,
		"color":       5814783,
		"footer":      map[string]interface{}{"text": "Bot Activity Log (golang)"},
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	}

	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(DISCORD_WEBHOOK_URL, "application/json", strings.NewReader(string(jsonPayload)))
	if err != nil {
		log.Printf("Failed to send message to Discord: %v", err)
	} else {
		defer resp.Body.Close()
	}
	if TELEGRAM_ENABLED != "" {
		payload := map[string]string{
			"chat_id": TELEGRAM_CHAT_ID,
			"text":    message,
		}

		jsonPayload, _ := json.Marshal(payload)
		resp, err := http.Post(fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TELEGRAM_BOT_TOKEN), "application/json", strings.NewReader(string(jsonPayload)))
		if err != nil {
			log.Printf("Failed to send message to Telegram: %v", err)
		} else {
			defer resp.Body.Close()
		}
	}
}

func startWatchdog() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write && event.Name == BOT_FILE_PATH {
					log.Printf("INFO: %s has been modified, updating hash...", BOT_FILE_PATH)

					// Check if the file is empty
					fileInfo, err := os.Stat(BOT_FILE_PATH)
					if err != nil {
						log.Printf("ERROR: Failed to get file info: %v", err)
						continue
					}
					if fileInfo.Size() == 0 {
						log.Printf("INFO: File is empty, skipping update and notification.")
						continue
					}

					// Calculate the file hash
					fileHash, err := calculateFileHash(BOT_FILE_PATH)
					if err != nil {
						log.Printf("ERROR: Failed to calculate file hash: %v", err)
						continue
					}

					// Skip if the hash is for an empty file (this killed me)
					if fileHash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
						log.Printf("INFO: File is empty, skipping update and notification.")
						continue
					}

					// Update the version file
					if err := updateVersionFile(fileHash); err != nil {
						log.Printf("ERROR: Failed to update version file: %v", err)
						continue
					}
					log.Printf("INFO: Updated hash: %s", fileHash)

					// Send notification to Discord and Telegram
					sendUpdateNotification(fileHash)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("ERROR: %v", err)
			}
		}
	}()

	if err := watcher.Add(filepath.Dir(BOT_FILE_PATH)); err != nil {
		log.Fatal(err)
	}

	<-done
}

func ensureLogFile() error {
	if _, err := os.Stat(LOG_FILE); os.IsNotExist(err) {
		if err := ioutil.WriteFile(LOG_FILE, []byte("[]"), 0644); err != nil {
			return err
		}
	}
	if _, err := os.Stat(TOKENS_FILE_PATH); os.IsNotExist(err) {
		if err := ioutil.WriteFile(TOKENS_FILE_PATH, []byte("{}"), 0644); err != nil {
			return err
		}
	}
	return nil
}

func sendDiscordMessage(data map[string]interface{}) {
    // Safely get memory_file_info with nil checks
    memoryFileInfo, _ := data["memory_file_info"].(map[string]interface{})
    if memoryFileInfo == nil {
        memoryFileInfo = make(map[string]interface{})
    }

    // Safely get file_size_bytes with default value
    fileSize, ok := memoryFileInfo["file_size_bytes"].(float64)
    if !ok {
        fileSize = 0 // Default value if missing or wrong type
    }

    // Safely get line_count with default value
    lineCount, ok := memoryFileInfo["line_count"]
    if !ok {
        lineCount = "unknown"
    }

    // Create embed with safe values
    embed := map[string]interface{}{
        "title":       "Bot Activated",
        "description": "",
        "color":       5814783,
        "fields": []map[string]interface{}{
            {"name": "Name", "value": data["name"], "inline": true},
            {"name": "Timestamp", "value": data["timestamp"], "inline": true},
            {"name": "Version", "value": data["version"], "inline": true},
            {"name": "Slash Commands", "value": data["slash_commands"], "inline": true},
            {"name": "Memory File Info", 
             "value": fmt.Sprintf("File size: %d bytes\nLine count: %v", int(fileSize), lineCount), 
             "inline": false},
        },
        "footer": map[string]interface{}{"text": "Bot Activity Log (golang)"},
    }

    payload := map[string]interface{}{
        "embeds": []map[string]interface{}{embed},
    }

    jsonPayload, err := json.Marshal(payload)
    if err != nil {
        log.Printf("Failed to marshal Discord payload: %v", err)
        return
    }

    resp, err := http.Post(DISCORD_WEBHOOK_URL, "application/json", strings.NewReader(string(jsonPayload)))
    if err != nil {
        log.Printf("Failed to send message to Discord: %v", err)
        return
    }
    defer resp.Body.Close()
}

func sendTelegramMessage(data map[string]interface{}) {
	if TELEGRAM_ENABLED == "" {
		return
	}

	// fuck my big chungus life :broken_heart:
	fileSize := int(data["memory_file_info"].(map[string]interface{})["file_size_bytes"].(float64))

	message := fmt.Sprintf(
		"Name: %v\nTimestamp: %v\nVersion: %v\nSlash Commands: %v\nMemory File Info:\n   ├ File Size: %d bytes\n   └ Line Count: %v\n",
		data["name"], data["timestamp"], data["version"], data["slash_commands"], fileSize, data["memory_file_info"].(map[string]interface{})["line_count"],
	)

	payload := map[string]string{
		"chat_id": TELEGRAM_CHAT_ID,
		"text":    message,
	}

	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TELEGRAM_BOT_TOKEN), "application/json", strings.NewReader(string(jsonPayload)))
	if err != nil {
		log.Printf("Failed to send message to Telegram: %v", err)
		return
	}
	defer resp.Body.Close()
}

func sendTelegramAuthFail(data map[string]interface{}, reason string) {
	if TELEGRAM_ENABLED == "" {
		return
	}

	message := fmt.Sprintf("Name: %v failed to authenticate!\nReason: %v", data["name"], reason)
	payload := map[string]string{
		"chat_id": TELEGRAM_CHAT_ID,
		"text":    message,
	}

	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TELEGRAM_BOT_TOKEN), "application/json", strings.NewReader(string(jsonPayload)))
	if err != nil {
		log.Printf("Failed to send message to Telegram: %v", err)
		return
	}
	defer resp.Body.Close()
}

func startTelegramBot() {
	if TELEGRAM_ENABLED == "" {
		log.Println("Telegram is not enabled. Skipping bot startup.")
		return
	}

	bot, err := tgbotapi.NewBotAPI(TELEGRAM_BOT_TOKEN)
	if err != nil {
		log.Fatalf("Failed to start Telegram bot: %v", err)
	}

	bot.Debug = true
	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil { // fuck my chungus life 2
			continue
		}

		switch update.Message.Command() {
		case "stop":
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Shutting down the server...")
			bot.Send(msg)
			log.Println("Received 'stop' command from Telegram. Shutting down...")
			os.Exit(0)

		case "info":
			msgText := fmt.Sprintf("Application built on %s from branch %s\n", BuildDate, BuildBranch)
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, msgText)
			bot.Send(msg)

		case "update":
			fmt.Printf("Updating for OS: %s, Architecture: %s\n", runtime.GOOS, runtime.GOARCH)

			// hot guess
			var binaryURL string
			switch runtime.GOOS {
			case "linux":
				switch runtime.GOARCH {
				case "amd64":
					binaryURL = "https://github.com/gooberinc/goober-central/releases/latest/download/goober-central-ubuntu-latest-amd64"
				case "arm64":
					binaryURL = "https://github.com/gooberinc/goober-central/releases/latest/download/goober-central-ubuntu-latest-arm64"
				default:
					msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Unsupported architecture for Linux.")
					bot.Send(msg)
					continue
				}
			case "windows":
				if runtime.GOARCH == "386" { // Windows LOVES auto compiling for 386 for whatever reason i think i downloaded golang for x32 systems by mistake
					binaryURL = "https://github.com/gooberinc/goober-central/releases/latest/download/goober-central-windows-latest-amd64.exe"
				} else if runtime.GOARCH == "amd64" {
					binaryURL = "https://github.com/gooberinc/goober-central/releases/latest/download/goober-central-windows-latest-amd64.exe"
				} else {
					msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Unsupported architecture for Windows.")
					bot.Send(msg)
					continue
				}
			default:
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Unsupported operating system.")
				bot.Send(msg)
				continue
			}

			// im not making good comments anymore man you can guess
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Downloading the latest release...")
			bot.Send(msg)

			resp, err := http.Get(binaryURL)
			if err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Failed to download the binary: %v", err))
				bot.Send(msg)
				continue
			}
			defer resp.Body.Close()

			tempFile, err := ioutil.TempFile("", "goober-central-*.exe")
			if err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Failed to create a temporary file: %v", err))
				bot.Send(msg)
				continue
			}
			defer os.Remove(tempFile.Name())

			if _, err := io.Copy(tempFile, resp.Body); err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Failed to save the binary: %v", err))
				bot.Send(msg)
				continue
			}

			tempFile.Close()

			currentExecutable, err := os.Executable()
			if err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Failed to get the current executable path: %v", err))
				bot.Send(msg)
				continue
			}

			backupFile := currentExecutable + ".bak"
			if err := os.Rename(currentExecutable, backupFile); err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Failed to rename the current binary: %v", err))
				bot.Send(msg)
				continue
			}

			if err := os.Rename(tempFile.Name(), currentExecutable); err != nil {
				msg := tgbotapi.NewMessage(update.Message.Chat.ID, fmt.Sprintf("Failed to replace the current binary: %v", err))
				bot.Send(msg)
				os.Rename(backupFile, currentExecutable)
				continue
			}

			msg = tgbotapi.NewMessage(update.Message.Chat.ID, "Update completed successfully. Restarting the server...")
			bot.Send(msg)

			os.Exit(0)

		default:
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, "Unknown command. Available commands: /stop, /info")
			bot.Send(msg)
		}
	}
}

func main() {
	log.Printf("Application built on %s from branch %s\n", BuildDate, BuildBranch)
	if err := ensureLogFile(); err != nil {
		log.Fatalf("ERROR: Failed to ensure log file: %v", err)
	}

	go startWatchdog()
	go startTelegramBot()

	r := gin.Default()
	r.Use(func(c *gin.Context) {
		log.Printf("Request: %s %s", c.Request.Method, c.Request.URL.Path)
		c.Next()
	})

	r.GET("/alert", func(c *gin.Context) {
	content, err := os.ReadFile("status.txt")
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to read status")
		return
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", content)
})


	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})


	r.POST("/check-if-available", func(c *gin.Context) {
		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			log.Printf("DEBUG: Invalid JSON received in /check-if-available")
			sendTelegramAuthFail(data, "Invalid JSON Received!")
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid JSON format"})
			return
		}

		name, ok := data["name"].(string)
		if !ok || name == "" {
			log.Printf("DEBUG: No name provided in /check-if-available")
			sendTelegramAuthFail(data, "No Name Given!")
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Name is required"})
			return
		}

		tokens, err := loadTokens()
		if err != nil {
			log.Printf("DEBUG: Failed to load tokens in /check-if-available: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Internal Server Error"})
			return
		}

		if _, exists := tokens[name]; exists {
			log.Printf("DEBUG: Name %s is already taken in /check-if-available", name)
			sendTelegramAuthFail(data, "Name is already taken!")
			c.JSON(http.StatusOK, gin.H{"available": false, "message": "Name already taken"})
			return
		}

		log.Printf("DEBUG: Name %s is available in /check-if-available", name)
		c.JSON(http.StatusOK, gin.H{"available": true})
	})

	r.POST("/register", func(c *gin.Context) {
		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			log.Printf("DEBUG: Invalid JSON received in /register")
			sendTelegramAuthFail(data, "Invalid JSON Received!")
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid JSON format"})
			return
		}

		name, ok := data["name"].(string)
		if !ok || name == "" {
			log.Printf("DEBUG: No name provided in /register")
			sendTelegramAuthFail(data, "Name is required!")
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Name is required"})
			return
		}

		token := uuid.New().String()

		tokens, err := loadTokens()
		if err != nil {
			log.Printf("DEBUG: Failed to load tokens in /register: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Internal Server Error"})
			return
		}

		if _, exists := tokens[name]; exists {
			log.Printf("DEBUG: Name %s is already registered in /register", name)
			sendTelegramAuthFail(data, "Name is already registered!")
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Name already registered"})
			return
		}

		tokens[name] = token
		if err := saveTokens(tokens); err != nil {
			log.Printf("DEBUG: Failed to save tokens in /register: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Internal Server Error"})
			return
		}

		log.Printf("DEBUG: Name %s registered successfully in /register", name)
		c.JSON(http.StatusOK, gin.H{"message": "Name registered successfully", "token": token})
	})

	r.POST("/info", func(c *gin.Context) {
		info := gin.H{
			"build_date":   BuildDate,
			"build_branch": BuildBranch,
			"love_from":    "WhatDidYouExpect",
		}
		c.JSON(http.StatusOK, info)
	})

	r.POST("/ping", func(c *gin.Context) {
		// First log that we received a ping request
		log.Println("DEBUG: Received /ping request")

		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			log.Printf("ERROR: Failed to parse JSON in /ping: %v", err)
			sendTelegramAuthFail(data, "Invalid JSON payload")
			c.JSON(http.StatusBadRequest, gin.H{
				"detail": "Invalid JSON payload",
				"error":  err.Error(),
			})
			return
		}
	
		// Log the received data for debugging
		log.Printf("DEBUG: Received data: %+v", data)
	
		name, ok := data["name"].(string)
		if !ok || name == "" {
			errMsg := "Name is required and must be a string"
			log.Printf("ERROR: %s", errMsg)
			sendTelegramAuthFail(data, errMsg)
			c.JSON(http.StatusBadRequest, gin.H{
				"detail": errMsg,
				"received_name": data["name"],
			})
			return
		}
	
		token, ok := data["token"].(string)
		if !ok || token == "" {
			errMsg := "Token is required and must be a string"
			log.Printf("ERROR: %s", errMsg)
			sendTelegramAuthFail(data, errMsg)
			c.JSON(http.StatusBadRequest, gin.H{
				"detail": errMsg,
				"received_token": data["token"],
			})
			return
		}
	
		// Add more defensive programming for memory_file_info
		memFileInfo, ok := data["memory_file_info"].(map[string]interface{})
		if !ok {
			log.Printf("WARN: memory_file_info missing or invalid in payload")
			// Either return error or provide defaults
			memFileInfo = map[string]interface{}{
				"file_size_bytes": 0,
				"line_count":      0,
			}
			data["memory_file_info"] = memFileInfo
		}
	
		tokens, err := loadTokens()
		if err != nil {
			log.Printf("ERROR: Failed to load tokens: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"detail": "Internal Server Error",
				"error":  err.Error(),
			})
			return
		}
	
		if storedToken, exists := tokens[name]; !exists || storedToken != token {
			log.Printf("ERROR: Invalid token for name '%s'", name)
			sendTelegramAuthFail(data, "Invalid name or token")
			c.JSON(http.StatusForbidden, gin.H{
				"detail": "Invalid name or token",
				"name":   name,
			})
			return
		}
	
		data["timestamp"] = time.Now().UTC().Format(time.RFC3339)
	
		// Handle log file operations with more error checking
		var logs []map[string]interface{}
		if fileContent, err := ioutil.ReadFile(LOG_FILE); err == nil {
			if err := json.Unmarshal(fileContent, &logs); err != nil {
				log.Printf("ERROR: Failed to parse log file: %v", err)
				// Initialize empty logs instead of failing
				logs = []map[string]interface{}{}
			}
		} else {
			log.Printf("WARN: Could not read log file, creating new one: %v", err)
			logs = []map[string]interface{}{}
		}
	
		logs = append([]map[string]interface{}{data}, logs...)
		file, err := json.MarshalIndent(logs, "", "    ")
		if err != nil {
			log.Printf("ERROR: Failed to marshal logs: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"detail": "Internal Server Error",
				"error":  err.Error(),
			})
			return
		}
	
		if err := ioutil.WriteFile(LOG_FILE, file, 0644); err != nil {
			log.Printf("ERROR: Failed to write logs: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"detail": "Internal Server Error",
				"error":  err.Error(),
			})
			return
		}
	
		// Send notifications with error handling
		go func() {
			if err := recover(); err != nil {
				log.Printf("ERROR: Panic in notification sending: %v", err)
			}
			sendDiscordMessage(data)
			sendTelegramMessage(data)
		}()
	
		log.Printf("INFO: Successfully processed ping from %s", name)
		c.JSON(http.StatusOK, gin.H{
			"message":   "Ping received successfully",
			"timestamp": data["timestamp"],
		})
	})
	
	r.StaticFile("/", "./static/index.html")  // serve index.html at root
	r.Static("/static", "./static")           // serve other files under /static/
	r.StaticFile("/latest_version.json", "./static/latest_version.json") // serve latest_version.json
	r.Static("/imgs", "./static/imgs")
	r.StaticFile("/robots.txt", "./static/robots.txt")
	r.Static("/goob", "./static/goob")


	
	log.Println("Starting server on :9094...")
	if err := r.Run(":9094"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
