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
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
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
					fileHash, err := calculateFileHash(BOT_FILE_PATH)
					if err != nil {
						log.Printf("ERROR: Failed to calculate file hash: %v", err)
						continue
					}
					if err := updateVersionFile(fileHash); err != nil {
						log.Printf("ERROR: Failed to update version file: %v", err)
						continue
					}
					log.Printf("INFO: Updated hash: %s", fileHash)
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
	embed := map[string]interface{}{
		"title":       "Bot Activated",
		"description": "",
		"color":       5814783,
		"fields": []map[string]interface{}{
			{"name": "Name", "value": data["name"], "inline": true},
			{"name": "Timestamp", "value": data["timestamp"], "inline": true},
			{"name": "Version", "value": data["version"], "inline": true},
			{"name": "Slash Commands", "value": data["slash_commands"], "inline": true},
			{"name": "Memory File Info", "value": fmt.Sprintf("File size: %v bytes\nLine count: %v", data["memory_file_info"].(map[string]interface{})["file_size_bytes"], data["memory_file_info"].(map[string]interface{})["line_count"]), "inline": false},
		},
		"footer": map[string]interface{}{"text": "Bot Activity Log (golang)"},
	}

	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	}

	jsonPayload, _ := json.Marshal(payload)
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

	message := fmt.Sprintf(
		"Name: %v\nTimestamp: %v\nVersion: %v\nSlash Commands: %v\nMemory File Info:\n   ├ File Size: %v bytes\n   └ Line Count: %v\n",
		data["name"], data["timestamp"], data["version"], data["slash_commands"], data["memory_file_info"].(map[string]interface{})["file_size_bytes"], data["memory_file_info"].(map[string]interface{})["line_count"],
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

func main() {
	if err := ensureLogFile(); err != nil {
		log.Fatalf("ERROR: Failed to ensure log file: %v", err)
	}

	go startWatchdog()
	r := gin.Default()
	r.Use(func(c *gin.Context) {
		log.Printf("Request: %s %s", c.Request.Method, c.Request.URL.Path)
		c.Next()
	})
	r.Static("/", filepath.Join(BASE_DIR, "static"))

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

	r.POST("/ping", func(c *gin.Context) {
		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			log.Printf("DEBUG: Invalid or missing JSON payload in /ping")
			sendTelegramAuthFail(data, "Invalid or missing JSON payload")
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid or missing JSON payload"})
			return
		}

		name, ok := data["name"].(string)
		if !ok || name == "" {
			log.Printf("DEBUG: Name is required in /ping")
			sendTelegramAuthFail(data, "Name and token are required")
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Name and token are required"})
			return
		}

		token, ok := data["token"].(string)
		if !ok || token == "" {
			log.Printf("DEBUG: Token is required in /ping")
			sendTelegramAuthFail(data, "Name and token are required")
			c.JSON(http.StatusBadRequest, gin.H{"detail": "Name and token are required"})
			return
		}

		tokens, err := loadTokens()
		if err != nil {
			log.Printf("DEBUG: Failed to load tokens in /ping: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Internal Server Error"})
			return
		}

		if storedToken, exists := tokens[name]; !exists || storedToken != token {
			log.Printf("DEBUG: Invalid name or token in /ping: name=%s, token=%s", name, token)
			sendTelegramAuthFail(data, "Invalid name or token. Please register again.")
			c.JSON(http.StatusForbidden, gin.H{"detail": "Invalid name or token. Please register again."})
			return
		}

		data["timestamp"] = time.Now().UTC().Format(time.RFC3339)

		logs := []map[string]interface{}{}
		if file, err := ioutil.ReadFile(LOG_FILE); err == nil {
			if err := json.Unmarshal(file, &logs); err != nil {
				log.Printf("DEBUG: Failed to unmarshal logs in /ping: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"detail": "Internal Server Error"})
				return
			}
		}

		logs = append([]map[string]interface{}{data}, logs...)
		file, err := json.MarshalIndent(logs, "", "    ")
		if err != nil {
			log.Printf("DEBUG: Failed to marshal logs in /ping: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Internal Server Error"})
			return
		}

		if err := ioutil.WriteFile(LOG_FILE, file, 0644); err != nil {
			log.Printf("DEBUG: Failed to write logs in /ping: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"detail": "Internal Server Error"})
			return
		}

		sendDiscordMessage(data)
		sendTelegramMessage(data)

		log.Printf("DEBUG: Ping received successfully in /ping: name=%s", name)
		c.JSON(http.StatusOK, gin.H{"message": "Ping received successfully", "timestamp": data["timestamp"]})
	})

	log.Println("Starting server on :9094...")
	if err := r.Run(":9094"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
