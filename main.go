package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// Data Structures
type Post struct {
	ID          int             `json:"id"`
	Title       string          `json:"title"`
	URL         string          `json:"url,omitempty"`
	Description string          `json:"description"`
	ImageURL    string          `json:"imageUrl,omitempty"`
	Votes       int             `json:"votes"`
	Timestamp   int64           `json:"timestamp"`
	Voters      map[string]bool `json:"voters"`
	Author      string          `json:"author"`
	AuthorIP    string          `json:"authorIP,omitempty"`
	Comments    []Comment       `json:"comments"`
	Replies     []Reply         `json:"replies,omitempty"`
	Pinned      bool            `json:"pinned"`
}

type Comment struct {
	ID        int    `json:"id"`
	Text      string `json:"text"`
	Author    string `json:"author"`
	Timestamp int64  `json:"timestamp"`
}

type Reply struct {
	ID        int    `json:"id"`
	Text      string `json:"text"`
	Author    string `json:"author"`
	Timestamp int64  `json:"timestamp"`
	CommentID int    `json:"commentId"`
}

type UserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type CommentRequest struct {
	Text      string `json:"text"`
	CommentID *int   `json:"commentId,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type Session struct {
	Username string
	Token    string
}

type UserProfile struct {
	AboutMe      string `json:"aboutMe"`
	ProfileImage string `json:"profileImage"`
}

// Global Variables and Constants
var posts []Post
var mutex sync.Mutex
var (
	adminUser string
	adminPass string
)

const postsDir = "posts"
const profilesDir = "profile_page"

var bannedIPs = make(map[string]bool)
var sessions = make(map[string]Session)

var rateLimiters = make(map[string]*rate.Limiter)
var rateMutex sync.Mutex

const rateLimit = 10
const rateWindow = time.Minute

var logFile *os.File

var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

// Initialization
func init() {
	// Load admin credentials from files
	userBytes, err1 := ioutil.ReadFile("adminUser")
	if err1 != nil {
		log.Fatalf("Error reading adminUser file: %v", err1)
	}
	adminUser = strings.TrimSpace(string(userBytes))

	passBytes, err2 := ioutil.ReadFile("adminPassword")
	if err2 != nil {
		log.Fatalf("Error reading adminPassword file: %v", err2)
	}
	adminPass = strings.TrimSpace(string(passBytes))

	// Ensure admin user is registered
	adminFilePath := filepath.Join("users", adminUser+".user")
	if _, err := os.Stat(adminFilePath); os.IsNotExist(err) {
		hashedPass, err := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("Error hashing admin password: %v", err)
		}
		if err := ioutil.WriteFile(adminFilePath, hashedPass, 0644); err != nil {
			log.Fatalf("Error writing admin user file: %v", err)
		}
		log.Printf("Admin user %s initialized with hashed password", adminUser)
	}

	// Set up logging
	var err error
	logFile, err = os.OpenFile("server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(logFile)

	// Create directories if they don't exist
	if err := os.MkdirAll(postsDir, 0755); err != nil {
		log.Fatal("Error creating posts directory:", err)
	}
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		log.Fatal("Error creating profiles directory:", err)
	}
	if err := os.MkdirAll("users", 0755); err != nil {
		log.Fatal("Error creating users directory:", err)
	}

	// Initialize posts and profiles
	loadPosts()
	ensureProfileFiles()
}

// Helper Functions
func loadPosts() {
	mutex.Lock()
	defer mutex.Unlock()

	posts = []Post{}
	files, err := ioutil.ReadDir(postsDir)
	if err != nil {
		log.Printf("Error reading posts directory: %v", err)
	}

	if len(files) == 0 {
		// Initialize with example posts if directory is empty
		posts = []Post{
			{ID: 1, Title: "Example Post", URL: "https://example.com", Description: "An example post", ImageURL: "https://example.com/img.jpg", Votes: 5, Timestamp: 1677654321, Voters: make(map[string]bool), Author: "admin", AuthorIP: "127.0.0.1", Comments: []Comment{}, Replies: []Reply{}},
			{ID: 2, Title: "Another Cool Post", URL: "https://another.com", Description: "Something interesting", ImageURL: "https://another.com/pic.png", Votes: 2, Timestamp: 1677654322, Voters: make(map[string]bool), Author: "user1", AuthorIP: "127.0.0.1", Comments: []Comment{}, Replies: []Reply{}},
		}
		for _, post := range posts {
			savePost(post)
		}
		log.Printf("Initialized posts directory with %d posts", len(posts))
		return
	}

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		data, err := ioutil.ReadFile(filepath.Join(postsDir, file.Name()))
		if err != nil {
			log.Printf("Error reading post file %s: %v", file.Name(), err)
			continue
		}
		var post Post
		if err := json.Unmarshal(data, &post); err != nil {
			log.Printf("Error unmarshaling post %s: %v", file.Name(), err)
			continue
		}
		if post.Voters == nil {
			post.Voters = make(map[string]bool)
		}
		if post.Comments == nil {
			post.Comments = []Comment{}
		}
		if post.Replies == nil {
			post.Replies = []Reply{}
		}
		posts = append(posts, post)
	}
	log.Printf("Loaded %d posts from posts directory", len(posts))
}

func savePost(post Post) {
	data, err := json.MarshalIndent(post, "", "  ")
	if err != nil {
		log.Printf("Error marshaling post %d: %v", post.ID, err)
		return
	}
	filePath := filepath.Join(postsDir, fmt.Sprintf("post_%d.json", post.ID))
	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		log.Printf("Error writing post %d to file: %v", post.ID, err)
	}
}

func deletePostFile(id int) {
	filePath := filepath.Join(postsDir, fmt.Sprintf("post_%d.json", id))
	if err := os.Remove(filePath); err != nil {
		log.Printf("Error deleting post file %d: %v", id, err)
	}
}

func loadProfile(username string) (UserProfile, error) {
	filePath := filepath.Join(profilesDir, username+".json")
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return UserProfile{}, nil // Return empty profile if file doesn't exist
		}
		return UserProfile{}, err
	}
	var profile UserProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return UserProfile{}, err
	}
	return profile, nil
}

func saveProfile(username string, profile UserProfile) error {
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	filePath := filepath.Join(profilesDir, username+".json")
	return ioutil.WriteFile(filePath, data, 0644)
}

func ensureProfileFiles() {
	usersDir := "users"
	files, err := ioutil.ReadDir(usersDir)
	if err != nil {
		log.Printf("Error reading users directory: %v", err)
		return
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".user") {
			username := strings.TrimSuffix(file.Name(), ".user")
			filePath := filepath.Join(profilesDir, username+".json")
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				defaultProfile := UserProfile{
					AboutMe:      "",
					ProfileImage: "default_profile.png",
				}
				if err := saveProfile(username, defaultProfile); err != nil {
					log.Printf("Error creating profile for %s: %v", username, err)
				}
			}
		}
	}
}

func sanitizeInput(input string) string {
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	return input
}

func checkRateLimit(ip string) bool {
	rateMutex.Lock()
	defer rateMutex.Unlock()

	limiter, exists := rateLimiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Every(rateWindow/rateLimit), rateLimit)
		rateLimiters[ip] = limiter
	}
	return limiter.Allow()
}

func getUsernameFromToken(token string) (string, bool) {
	session, exists := sessions[token]
	if !exists {
		return "", false
	}
	return session.Username, true
}

func saveBannedIPs() {
	var lines []string
	for ip := range bannedIPs {
		lines = append(lines, ip)
	}
	data := strings.Join(lines, "\n")
	ioutil.WriteFile("banned_ips.txt", []byte(data), 0644)
}

func loadBannedIPs() {
	data, err := ioutil.ReadFile("banned_ips.txt")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, ip := range lines {
		if ip != "" {
			bannedIPs[ip] = true
		}
	}
}

func sendError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(ErrorResponse{Error: message})
}

func proxyImage(w http.ResponseWriter, r *http.Request) {
	if bannedIPs[r.RemoteAddr] {
		log.Printf("Blocked banned IP: %s on proxyImage", r.RemoteAddr)
		sendError(w, "Your IP is banned", http.StatusForbidden)
		return
	}

	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on proxyImage", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	rawURL := r.URL.Query().Get("url")
	if rawURL == "" {
		sendError(w, "Missing url parameter", http.StatusBadRequest)
		return
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		sendError(w, "Invalid url parameter", http.StatusBadRequest)
		return
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		sendError(w, "Only http and https schemes are supported", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		log.Printf("Error creating proxy request for %s: %v", rawURL, err)
		sendError(w, "Unable to fetch image", http.StatusBadGateway)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error fetching %s: %v", rawURL, err)
		sendError(w, "Unable to fetch image", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Non-200 response for %s: %d", rawURL, resp.StatusCode)
		sendError(w, "Unable to fetch image", http.StatusBadGateway)
		return
	}

	reader := io.Reader(resp.Body)
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" || !strings.HasPrefix(contentType, "image/") {
		peek, err := io.ReadAll(io.LimitReader(resp.Body, 512))
		if err != nil {
			log.Printf("Error peeking content for %s: %v", rawURL, err)
			sendError(w, "Unable to fetch image", http.StatusBadGateway)
			return
		}

		detected := http.DetectContentType(peek)
		if !strings.HasPrefix(detected, "image/") {
			log.Printf("Content %s detected as %s", rawURL, detected)
			sendError(w, "Unsupported content type", http.StatusUnsupportedMediaType)
			return
		}

		contentType = detected
		reader = io.MultiReader(bytes.NewReader(peek), resp.Body)
	}

	w.Header().Set("Content-Type", contentType)
	if resp.ContentLength > 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if _, err := io.Copy(w, reader); err != nil {
		log.Printf("Error streaming proxied image %s: %v", rawURL, err)
	}
}

// HTTP Handlers
func getPosts(w http.ResponseWriter, r *http.Request) {
	if bannedIPs[r.RemoteAddr] {
		log.Printf("Blocked banned IP: %s", r.RemoteAddr)
		sendError(w, "Your IP is banned", http.StatusForbidden)
		return
	}

	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	sortBy := r.URL.Query().Get("sort")
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 10
	}

	visiblePosts := []Post{}
	pinnedPosts := []Post{}

	token := r.Header.Get("X-Session-Token")
	username, _ := getUsernameFromToken(token)

	for _, post := range posts {
		if username != adminUser {
			post.AuthorIP = "" // Hide IP from non-admins
		}
		if post.Pinned {
			pinnedPosts = append(pinnedPosts, post)
		} else {
			visiblePosts = append(visiblePosts, post)
		}
	}

	sort.Slice(visiblePosts, func(i, j int) bool {
		return visiblePosts[i].Timestamp > visiblePosts[j].Timestamp
	})

	if sortBy == "votes" {
		sort.Slice(visiblePosts, func(i, j int) bool {
			return visiblePosts[i].Votes > visiblePosts[j].Votes
		})
	}

	start := (page - 1) * limit
	end := start + limit

	if start > len(visiblePosts) {
		start = len(visiblePosts)
	}
	if end > len(visiblePosts) {
		end = len(visiblePosts)
	}

	paginatedPosts := visiblePosts[start:end]

	result := append(pinnedPosts, paginatedPosts...)

	response := struct {
		Posts      []Post `json:"posts"`
		Total      int    `json:"total"`
		Page       int    `json:"page"`
		Limit      int    `json:"limit"`
		TotalPages int    `json:"totalPages"`
	}{
		Posts:      result,
		Total:      len(visiblePosts),
		Page:       page,
		Limit:      limit,
		TotalPages: int(math.Ceil(float64(len(visiblePosts)) / float64(limit))),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func createPost(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on createPost", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	token := r.Header.Get("X-Session-Token")
	username, valid := getUsernameFromToken(token)
	if !valid {
		log.Printf("Unauthorized attempt to create post from IP: %s", r.RemoteAddr)
		sendError(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	if bannedIPs[r.RemoteAddr] {
		log.Printf("Blocked banned IP: %s on createPost", r.RemoteAddr)
		sendError(w, "Your IP is banned", http.StatusForbidden)
		return
	}

	var newPost Post
	if err := json.NewDecoder(r.Body).Decode(&newPost); err != nil {
		log.Printf("Error decoding JSON from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Error decoding JSON", http.StatusBadRequest)
		return
	}

	if newPost.Title == "" || newPost.Description == "" {
		log.Printf("Missing required fields from IP: %s", r.RemoteAddr)
		sendError(w, "Title and description are required", http.StatusBadRequest)
		return
	}

	if len(newPost.Title) > 200 {
		log.Printf("Title too long from IP: %s", r.RemoteAddr)
		sendError(w, "Title must be 200 characters or less", http.StatusBadRequest)
		return
	}
	if len(newPost.Description) > 1000 {
		log.Printf("Description too long from IP: %s", r.RemoteAddr)
		sendError(w, "Description must be 1000 characters or less", http.StatusBadRequest)
		return
	}
	if len(newPost.URL) > 500 {
		log.Printf("URL too long from IP: %s", r.RemoteAddr)
		sendError(w, "URL must be 500 characters or less", http.StatusBadRequest)
		return
	}
	if len(newPost.ImageURL) > 500 {
		log.Printf("Image URL too long from IP: %s", r.RemoteAddr)
		sendError(w, "Image URL must be 500 characters or less", http.StatusBadRequest)
		return
	}

	newPost.Title = sanitizeInput(newPost.Title)
	newPost.Description = sanitizeInput(newPost.Description)
	newPost.URL = sanitizeInput(newPost.URL)
	newPost.ImageURL = sanitizeInput(newPost.ImageURL)

	mutex.Lock()
	defer mutex.Unlock()

	// Simple ID generation using a counter file
	countFile := "count.txt"
	countBytes, err := ioutil.ReadFile(countFile)
	count := 1
	if err == nil {
		count, _ = strconv.Atoi(strings.TrimSpace(string(countBytes)))
		count++
	} else {
		ioutil.WriteFile(countFile, []byte("1"), 0644)
	}

	newPost.ID = count
	newPost.Votes = 0
	newPost.Timestamp = time.Now().Unix()
	newPost.Voters = make(map[string]bool)
	newPost.Author = username
	newPost.AuthorIP = r.RemoteAddr
	newPost.Comments = []Comment{}
	newPost.Replies = []Reply{}
	posts = append(posts, newPost)
	savePost(newPost)

	// Update counter
	ioutil.WriteFile(countFile, []byte(strconv.Itoa(count)), 0644)

	log.Printf("Post created by %s from IP: %s, ID: %d", username, r.RemoteAddr, newPost.ID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newPost)
}

func upvotePost(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on upvotePost", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	token := r.Header.Get("X-Session-Token")
	username, valid := getUsernameFromToken(token)
	if !valid {
		log.Printf("Unauthorized attempt to upvote from IP: %s", r.RemoteAddr)
		sendError(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	if bannedIPs[r.RemoteAddr] {
		log.Printf("Blocked banned IP: %s on upvotePost", r.RemoteAddr)
		sendError(w, "Your IP is banned", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		log.Printf("Invalid ID from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	for i, post := range posts {
		if post.ID == id {
			if post.Voters[username] {
				log.Printf("Duplicate upvote attempt by %s on post %d from IP: %s", username, id, r.RemoteAddr)
				sendError(w, "You have already voted on this post", http.StatusForbidden)
				return
			}
			posts[i].Votes++
			posts[i].Voters[username] = true
			savePost(posts[i])
			log.Printf("Upvote added by %s on post %d from IP: %s", username, id, r.RemoteAddr)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(posts[i])
			return
		}
	}

	sendError(w, "Post not found", http.StatusNotFound)
}

func deletePost(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on deletePost", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	token := r.Header.Get("X-Session-Token")
	username, valid := getUsernameFromToken(token)
	if !valid {
		log.Printf("Unauthorized attempt to delete post from IP: %s", r.RemoteAddr)
		sendError(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	if bannedIPs[r.RemoteAddr] {
		log.Printf("Blocked banned IP: %s on deletePost", r.RemoteAddr)
		sendError(w, "Your IP is banned", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		log.Printf("Invalid ID from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	for i, post := range posts {
		if post.ID == id {
			if post.Author != username && username != adminUser {
				log.Printf("User %s attempted to delete post %d owned by %s from IP: %s", username, id, post.Author, r.RemoteAddr)
				sendError(w, "You can only delete your own posts", http.StatusForbidden)
				return
			}
			posts = append(posts[:i], posts[i+1:]...)
			deletePostFile(id)
			log.Printf("Post %d deleted by %s from IP: %s", id, username, r.RemoteAddr)
			fmt.Fprintf(w, "Post deleted")
			return
		}
	}

	sendError(w, "Post not found", http.StatusNotFound)
}

func pinPost(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on pinPost", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	token := r.Header.Get("X-Session-Token")
	username, valid := getUsernameFromToken(token)
	if !valid || username != adminUser {
		log.Printf("Unauthorized attempt to pin post from IP: %s", r.RemoteAddr)
		sendError(w, "Only the administrator can pin posts", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		log.Printf("Invalid ID from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	for i, post := range posts {
		if post.ID == id {
			posts[i].Pinned = true
			savePost(posts[i])
			log.Printf("Post %d pinned by admin %s from IP: %s", id, username, r.RemoteAddr)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(posts[i])
			return
		}
	}

	sendError(w, "Post not found", http.StatusNotFound)
}

func unpinPost(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on unpinPost", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	token := r.Header.Get("X-Session-Token")
	username, valid := getUsernameFromToken(token)
	if !valid || username != adminUser {
		log.Printf("Unauthorized attempt to unpin post from IP: %s", r.RemoteAddr)
		sendError(w, "Only the administrator can unpin posts", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		log.Printf("Invalid ID from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	for i, post := range posts {
		if post.ID == id {
			posts[i].Pinned = false
			savePost(posts[i])
			log.Printf("Post %d unpinned by admin %s from IP: %s", id, username, r.RemoteAddr)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(posts[i])
			return
		}
	}

	sendError(w, "Post not found", http.StatusNotFound)
}

func addComment(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on addComment", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	token := r.Header.Get("X-Session-Token")
	username, valid := getUsernameFromToken(token)
	if !valid {
		log.Printf("Unauthorized attempt to add comment from IP: %s", r.RemoteAddr)
		sendError(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	if bannedIPs[r.RemoteAddr] {
		log.Printf("Blocked banned IP: %s on addComment", r.RemoteAddr)
		sendError(w, "Your IP is banned", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	postId, err := strconv.Atoi(vars["id"])
	if err != nil {
		log.Printf("Invalid post ID from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Invalid post ID", http.StatusBadRequest)
		return
	}

	var commentReq CommentRequest
	if err := json.NewDecoder(r.Body).Decode(&commentReq); err != nil {
		log.Printf("Error decoding JSON from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Error decoding JSON", http.StatusBadRequest)
		return
	}

	if commentReq.Text == "" {
		log.Printf("Missing comment text from IP: %s", r.RemoteAddr)
		sendError(w, "Comment text is required", http.StatusBadRequest)
		return
	}

	commentReq.Text = sanitizeInput(commentReq.Text)

	mutex.Lock()
	defer mutex.Unlock()

	for i, post := range posts {
		if post.ID == postId {
			if commentReq.CommentID != nil {
				// Add reply
				replyId := len(post.Replies) + 1
				reply := Reply{
					ID:        replyId,
					Text:      commentReq.Text,
					Author:    username,
					Timestamp: time.Now().Unix(),
					CommentID: *commentReq.CommentID,
				}
				posts[i].Replies = append(posts[i].Replies, reply)
				log.Printf("Reply added by %s to comment %d on post %d from IP: %s", username, *commentReq.CommentID, postId, r.RemoteAddr)
			} else {
				// Add comment
				commentId := len(post.Comments) + 1
				comment := Comment{
					ID:        commentId,
					Text:      commentReq.Text,
					Author:    username,
					Timestamp: time.Now().Unix(),
				}
				posts[i].Comments = append(posts[i].Comments, comment)
				log.Printf("Comment added by %s on post %d from IP: %s", username, postId, r.RemoteAddr)
			}
			savePost(posts[i])
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(posts[i])
			return
		}
	}

	sendError(w, "Post not found", http.StatusNotFound)
}

func deleteComment(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on deleteComment", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	token := r.Header.Get("X-Session-Token")
	username, valid := getUsernameFromToken(token)
	if !valid || username != adminUser {
		log.Printf("Unauthorized attempt to delete comment from IP: %s", r.RemoteAddr)
		sendError(w, "Only the administrator can delete comments", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	postId, err := strconv.Atoi(vars["postId"])
	if err != nil {
		log.Printf("Invalid post ID from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Invalid post ID", http.StatusBadRequest)
		return
	}
	commentId, err := strconv.Atoi(vars["commentId"])
	if err != nil {
		log.Printf("Invalid comment ID from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Invalid comment ID", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	for i, post := range posts {
		if post.ID == postId {
			for j, comment := range post.Comments {
				if comment.ID == commentId {
					posts[i].Comments = append(posts[i].Comments[:j], posts[i].Comments[j+1:]...)
					savePost(posts[i])
					log.Printf("Comment %d deleted by admin %s from post %d from IP: %s", commentId, username, postId, r.RemoteAddr)
					fmt.Fprintf(w, "Comment deleted")
					return
				}
			}
			sendError(w, "Comment not found", http.StatusNotFound)
			return
		}
	}

	sendError(w, "Post not found", http.StatusNotFound)
}

func deleteReply(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on deleteReply", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	token := r.Header.Get("X-Session-Token")
	username, valid := getUsernameFromToken(token)
	if !valid || username != adminUser {
		log.Printf("Unauthorized attempt to delete reply from IP: %s", r.RemoteAddr)
		sendError(w, "Only the administrator can delete replies", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	postId, err := strconv.Atoi(vars["postId"])
	if err != nil {
		log.Printf("Invalid post ID from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Invalid post ID", http.StatusBadRequest)
		return
	}
	replyId, err := strconv.Atoi(vars["replyId"])
	if err != nil {
		log.Printf("Invalid reply ID from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Invalid reply ID", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	for i, post := range posts {
		if post.ID == postId {
			for j, reply := range post.Replies {
				if reply.ID == replyId {
					posts[i].Replies = append(posts[i].Replies[:j], posts[i].Replies[j+1:]...)
					savePost(posts[i])
					log.Printf("Reply %d deleted by admin %s from post %d from IP: %s", replyId, username, postId, r.RemoteAddr)
					fmt.Fprintf(w, "Reply deleted")
					return
				}
			}
			sendError(w, "Reply not found", http.StatusNotFound)
			return
		}
	}

	sendError(w, "Post not found", http.StatusNotFound)
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on registerUser", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	var userReq UserRequest
	if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
		log.Printf("Error decoding JSON from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Error decoding JSON", http.StatusBadRequest)
		return
	}
	username := userReq.Username
	password := userReq.Password

	if !usernameRegex.MatchString(username) {
		log.Printf("Invalid username format from IP: %s: %s", r.RemoteAddr, username)
		sendError(w, "Username must contain only letters and numbers", http.StatusBadRequest)
		return
	}

	filePath := filepath.Join("users", username+".user")
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		log.Printf("Username %s already exists from IP: %s", username, r.RemoteAddr)
		sendError(w, "Username already exists", http.StatusConflict)
		return
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password for %s from IP: %s: %v", username, r.RemoteAddr, err)
		sendError(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	if err := ioutil.WriteFile(filePath, hashedPass, 0644); err != nil {
		log.Printf("Error writing user file for %s from IP: %s: %v", username, r.RemoteAddr, err)
		sendError(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	// Create default profile with corrected field name
	defaultProfile := UserProfile{
		AboutMe:      "",
		ProfileImage: "default_profile.png",
	}
	if err := saveProfile(username, defaultProfile); err != nil {
		log.Printf("Error creating profile for %s: %v", username, err)
	}

	log.Printf("User %s registered from IP: %s", username, r.RemoteAddr)
	fmt.Fprintf(w, "User registered successfully")
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on loginUser", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	var userReq UserRequest
	if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
		log.Printf("Error decoding login request from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Error decoding JSON", http.StatusBadRequest)
		return
	}
	username := userReq.Username
	password := userReq.Password

	filePath := filepath.Join("users", username+".user")
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Printf("User %s not found from IP: %s", username, r.RemoteAddr)
		sendError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	storedHash := strings.TrimSpace(string(data))
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password)); err != nil {
		log.Printf("Invalid password for user %s from IP: %s", username, r.RemoteAddr)
		sendError(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Session creation
	token := uuid.New().String()
	sessions[token] = Session{Username: username, Token: token}
	http.SetCookie(w, &http.Cookie{
		Name:  "session_token",
		Value: token,
		Path:  "/",
	})
	log.Printf("User %s logged in from IP: %s", username, r.RemoteAddr)
	fmt.Fprintf(w, "Login successful")
}

func logoutUser(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Session-Token")
	if token == "" {
		sendError(w, "No session token provided", http.StatusUnauthorized)
		return
	}
	delete(sessions, token)
	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	log.Printf("User logged out from IP: %s", r.RemoteAddr)
	fmt.Fprintf(w, "Logout successful")
}

func banUser(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on banUser", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	token := r.Header.Get("X-Session-Token")
	username, valid := getUsernameFromToken(token)
	if !valid || username != adminUser {
		log.Printf("Unauthorized attempt to ban user from IP: %s", r.RemoteAddr)
		sendError(w, "Only the administrator can ban users", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	targetUser := vars["username"]

	filePath := filepath.Join("users", targetUser+".user")
	if err := os.Remove(filePath); err != nil {
		log.Printf("Failed to ban user %s from IP: %s: %v", targetUser, r.RemoteAddr, err)
		sendError(w, "User not found or error banning", http.StatusNotFound)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()
	for i := range posts {
		if posts[i].Author == targetUser {
			posts[i].Author = "[Banned]"
			savePost(posts[i])
		}
		for j := range posts[i].Comments {
			if posts[i].Comments[j].Author == targetUser {
				posts[i].Comments[j].Author = "[Banned]"
			}
		}
		for j := range posts[i].Replies {
			if posts[i].Replies[j].Author == targetUser {
				posts[i].Replies[j].Author = "[Banned]"
			}
		}
	}

	log.Printf("User %s banned by admin %s from IP: %s", targetUser, username, r.RemoteAddr)
	fmt.Fprintf(w, "User %s banned", targetUser)
}

func banIP(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on banIP", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	token := r.Header.Get("X-Session-Token")
	username, valid := getUsernameFromToken(token)
	if !valid || username != adminUser {
		log.Printf("Unauthorized attempt to ban IP from IP: %s", r.RemoteAddr)
		sendError(w, "Only the administrator can ban IPs", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	ip := vars["ip"]

	mutex.Lock()
	defer mutex.Unlock()
	bannedIPs[ip] = true
	saveBannedIPs()

	log.Printf("IP %s banned by admin %s from IP: %s", ip, username, r.RemoteAddr)
	fmt.Fprintf(w, "IP %s banned", ip)
}

func getUserProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	profile, err := loadProfile(username)
	if err != nil {
		log.Printf("Error loading profile for %s: %v", username, err)
		sendError(w, "Error loading profile", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

func updateUserProfile(w http.ResponseWriter, r *http.Request) {
	if !checkRateLimit(r.RemoteAddr) {
		log.Printf("Rate limit exceeded for IP: %s on updateUserProfile", r.RemoteAddr)
		sendError(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	token := r.Header.Get("X-Session-Token")
	username, valid := getUsernameFromToken(token)
	if !valid {
		log.Printf("Unauthorized attempt to update profile from IP: %s", r.RemoteAddr)
		sendError(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	targetUsername := vars["username"]
	if username != targetUsername {
		log.Printf("User %s attempted to update profile of %s from IP: %s", username, targetUsername, r.RemoteAddr)
		sendError(w, "You can only update your own profile", http.StatusForbidden)
		return
	}

	var profile UserProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		log.Printf("Error decoding JSON from IP: %s: %v", r.RemoteAddr, err)
		sendError(w, "Error decoding JSON", http.StatusBadRequest)
		return
	}

	profile.AboutMe = sanitizeInput(profile.AboutMe)
	profile.ProfileImage = sanitizeInput(profile.ProfileImage)

	if err := saveProfile(username, profile); err != nil {
		log.Printf("Error saving profile for %s: %v", username, err)
		sendError(w, "Error saving profile", http.StatusInternalServerError)
		return
	}

	log.Printf("Profile updated for %s from IP: %s", username, r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

// Note: getUsername is referenced in the router but not defined in the original code.
// Adding a simple implementation here to ensure the code compiles.
func getUsername(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Session-Token")
	username, valid := getUsernameFromToken(token)
	if !valid {
		sendError(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"username": username})
}

func main() {
	loadBannedIPs()

	router := mux.NewRouter()

	router.HandleFunc("/posts", getPosts).Methods("GET")
	router.HandleFunc("/posts", createPost).Methods("POST")
	router.HandleFunc("/posts/{id}/upvote", upvotePost).Methods("POST")
	router.HandleFunc("/posts/{id}", deletePost).Methods("DELETE")
	router.HandleFunc("/posts/{id}/pin", pinPost).Methods("POST")
	router.HandleFunc("/posts/{id}/unpin", unpinPost).Methods("POST")
	router.HandleFunc("/posts/{id}/comments", addComment).Methods("POST")
	router.HandleFunc("/posts/{postId}/comments/{commentId}", deleteComment).Methods("DELETE")
	router.HandleFunc("/posts/{postId}/replies/{replyId}", deleteReply).Methods("DELETE")
	router.HandleFunc("/register", registerUser).Methods("POST")
	router.HandleFunc("/login", loginUser).Methods("POST")
	router.HandleFunc("/logout", logoutUser).Methods("POST")
	router.HandleFunc("/ban/user/{username}", banUser).Methods("POST")
	router.HandleFunc("/ban/ip/{ip}", banIP).Methods("POST")
	router.HandleFunc("/username", getUsername).Methods("GET")
	router.HandleFunc("/profiles/{username}", getUserProfile).Methods("GET")
	router.HandleFunc("/profiles/{username}", updateUserProfile).Methods("PUT")
	router.HandleFunc("/image-proxy", proxyImage).Methods("GET")

	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./public")))

	fmt.Println("Server running at https://localhost:443 (or http://localhost:3000 if certs missing)")
	err := http.ListenAndServeTLS(":443", "cert.pem", "key.pem", router)
	if err != nil {
		log.Printf("TLS failed, falling back to HTTP: %v", err)
		log.Fatal(http.ListenAndServe(":3000", router))
	}
}
