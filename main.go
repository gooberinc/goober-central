package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
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

func main() {
	log.Printf("Application built on %s from branch %s\n", BuildDate, BuildBranch)
	if err := ensureLogFile(); err != nil {
		log.Fatalf("ERROR: Failed to ensure log file: %v", err)
	}

	go startWatchdog()

	r := gin.Default()
	r.Use(func(c *gin.Context) {
		log.Printf("Request: %s %s", c.Request.Method, c.Request.URL.Path)
		c.Next()
	})
	r.StaticFile("/latest_version.json", filepath.Join(BASE_DIR, "static", "latest_version.json"))

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

			c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid JSON format"})
			return
		}

		name, ok := data["name"].(string)
		if !ok || name == "" {
			log.Printf("DEBUG: No name provided in /check-if-available")

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

			c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid JSON format"})
			return
		}

		name, ok := data["name"].(string)
		if !ok || name == "" {
			log.Printf("DEBUG: No name provided in /register")

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

			c.JSON(http.StatusBadRequest, gin.H{"detail": "Invalid or missing JSON payload"})
			return
		}

		name, ok := data["name"].(string)
		if !ok || name == "" {
			log.Printf("DEBUG: Name is required in /ping")

			c.JSON(http.StatusBadRequest, gin.H{"detail": "Name and token are required"})
			return
		}

		token, ok := data["token"].(string)
		if !ok || token == "" {
			log.Printf("DEBUG: Token is required in /ping")

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

		log.Printf("DEBUG: Ping received successfully in /ping: name=%s", name)
		c.JSON(http.StatusOK, gin.H{"message": "Ping received successfully", "timestamp": data["timestamp"]})
	})

	log.Println("Starting server on :9094...")
	if err := r.Run(":9094"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
