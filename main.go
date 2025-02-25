package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "path/filepath"
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

var posts []Post
var mutex sync.Mutex
var (
    adminUser string
    adminPass string
)
const postsDir = "posts"
var bannedIPs = make(map[string]bool)
var sessions = make(map[string]Session)

var rateLimiters = make(map[string]*rate.Limiter)
var rateMutex sync.Mutex
const rateLimit = 10
const rateWindow = time.Minute

var logFile *os.File

func init() {
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

    var err error
    logFile, err = os.OpenFile("server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal(err)
    }
    log.SetOutput(logFile)

    if err := os.MkdirAll(postsDir, 0755); err != nil {
        log.Fatal("Error creating posts directory:", err)
    }

    loadPosts()
}

func loadPosts() {
    mutex.Lock()
    defer mutex.Unlock()

    posts = []Post{}
    files, err := ioutil.ReadDir(postsDir)
    if err != nil {
        log.Printf("Error reading posts directory: %v", err)
    }

    if len(files) == 0 {
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

func sanitizeInput(input string) string {
    input = strings.ReplaceAll(input, "<", "<")
    input = strings.ReplaceAll(input, ">", ">")
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
    visiblePosts := []Post{}
    pinnedPosts := []Post{}

    token := r.Header.Get("X-Session-Token")
    username, _ := getUsernameFromToken(token)

    for _, post := range posts {
        if username != adminUser {
            post.AuthorIP = ""
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
    if len(visiblePosts) > 60 {
        visiblePosts = visiblePosts[:60]
    }

    if sortBy == "votes" {
        sort.Slice(visiblePosts, func(i, j int) bool {
            return visiblePosts[i].Votes > visiblePosts[j].Votes
        })
    }

    result := append(pinnedPosts, visiblePosts...)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(result)
}

func getUsernameFromToken(token string) (string, bool) {
    session, exists := sessions[token]
    if !exists {
        return "", false
    }
    return session.Username, true
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

    content, err := os.ReadFile("count.txt")
    if err != nil {
        log.Fatal(err)
    }
    int1, err := strconv.Atoi(string(content))
    new_content := strconv.Itoa(int1 + 1)
    if err := os.WriteFile("count.txt", []byte(new_content), 0666); err != nil {
        log.Fatal(err)
    }

    newPost.ID = int1
    newPost.Votes = 0
    newPost.Timestamp = time.Now().Unix()
    newPost.Voters = make(map[string]bool)
    newPost.Author = username
    newPost.AuthorIP = r.RemoteAddr
    newPost.Comments = []Comment{}
    newPost.Replies = []Reply{}
    posts = append(posts, newPost)
    savePost(newPost)

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
                log.Printf("Unauthorized delete attempt by %s on post %d from IP: %s", username, id, r.RemoteAddr)
                sendError(w, "Only the author or administrator can delete this post", http.StatusForbidden)
                return
            }
            posts = append(posts[:i], posts[i+1:]...)
            deletePostFile(id)
            log.Printf("Post %d deleted by %s from IP: %s", id, username, r.RemoteAddr)
            w.WriteHeader(http.StatusOK)
            fmt.Fprintf(w, "Post %d deleted", id)
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
    id, err := strconv.Atoi(vars["id"])
    if err != nil {
        log.Printf("Invalid ID from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Invalid ID", http.StatusBadRequest)
        return
    }

    var commentReq CommentRequest
    if err := json.NewDecoder(r.Body).Decode(&commentReq); err != nil {
        log.Printf("Error decoding JSON from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Error decoding JSON", http.StatusBadRequest)
        return
    }

    if len(commentReq.Text) > 1000 {
        log.Printf("Comment too long from IP: %s", r.RemoteAddr)
        sendError(w, "Comment must be 1000 characters or less", http.StatusBadRequest)
        return
    }

    commentReq.Text = sanitizeInput(commentReq.Text)

    mutex.Lock()
    defer mutex.Unlock()

    for i, post := range posts {
        if post.ID == id {
            if commentReq.CommentID != nil {
                commentExists := false
                for _, comment := range post.Comments {
                    if comment.ID == *commentReq.CommentID {
                        commentExists = true
                        break
                    }
                }
                if !commentExists {
                    sendError(w, "Parent comment not found", http.StatusNotFound)
                    return
                }

                newReply := Reply{
                    ID:        generateReplyID(post.Replies),
                    Text:      commentReq.Text,
                    Author:    username,
                    Timestamp: time.Now().Unix(),
                    CommentID: *commentReq.CommentID,
                }
                posts[i].Replies = append(posts[i].Replies, newReply)
                savePost(posts[i])
                log.Printf("Reply added by %s to comment %d on post %d from IP: %s", 
                    username, *commentReq.CommentID, id, r.RemoteAddr)
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(newReply)
            } else {
                newComment := Comment{
                    ID:        len(post.Comments) + 1,
                    Text:      commentReq.Text,
                    Author:    username,
                    Timestamp: time.Now().Unix(),
                }
                posts[i].Comments = append(posts[i].Comments, newComment)
                savePost(posts[i])
                log.Printf("Comment added by %s on post %d from IP: %s", username, id, r.RemoteAddr)
                w.Header().Set("Content-Type", "application/json")
                json.NewEncoder(w).Encode(newComment)
            }
            return
        }
    }

    sendError(w, "Post not found", http.StatusNotFound)
}

func addReply(w http.ResponseWriter, r *http.Request) {
    if !checkRateLimit(r.RemoteAddr) {
        log.Printf("Rate limit exceeded for IP: %s on addReply", r.RemoteAddr)
        sendError(w, "Too many requests", http.StatusTooManyRequests)
        return
    }

    token := r.Header.Get("X-Session-Token")
    username, valid := getUsernameFromToken(token)
    if !valid {
        log.Printf("Unauthorized attempt to add reply from IP: %s", r.RemoteAddr)
        sendError(w, "User not authenticated", http.StatusUnauthorized)
        return
    }
    if bannedIPs[r.RemoteAddr] {
        log.Printf("Blocked banned IP: %s on addReply", r.RemoteAddr)
        sendError(w, "Your IP is banned", http.StatusForbidden)
        return
    }

    vars := mux.Vars(r)
    postID, err := strconv.Atoi(vars["postId"])
    if err != nil {
        log.Printf("Invalid post ID from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Invalid post ID", http.StatusBadRequest)
        return
    }
    commentID, err := strconv.Atoi(vars["commentId"])
    if err != nil {
        log.Printf("Invalid comment ID from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Invalid comment ID", http.StatusBadRequest)
        return
    }

    var commentReq CommentRequest
    if err := json.NewDecoder(r.Body).Decode(&commentReq); err != nil {
        log.Printf("Error decoding JSON from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Error decoding JSON", http.StatusBadRequest)
        return
    }

    if len(commentReq.Text) > 1000 {
        log.Printf("Reply too long from IP: %s", r.RemoteAddr)
        sendError(w, "Reply must be 1000 characters or less", http.StatusBadRequest)
        return
    }

    commentReq.Text = sanitizeInput(commentReq.Text)

    mutex.Lock()
    defer mutex.Unlock()

    for i, post := range posts {
        if post.ID == postID {
            commentExists := false
            for _, comment := range post.Comments {
                if comment.ID == commentID {
                    commentExists = true
                    break
                }
            }
            if !commentExists {
                sendError(w, "Comment not found", http.StatusNotFound)
                return
            }

            newReply := Reply{
                ID:        generateReplyID(post.Replies),
                Text:      commentReq.Text,
                Author:    username,
                Timestamp: time.Now().Unix(),
                CommentID: commentID,
            }
            
            posts[i].Replies = append(posts[i].Replies, newReply)
            savePost(posts[i])
            log.Printf("Reply added by %s to comment %d on post %d from IP: %s", 
                username, commentID, postID, r.RemoteAddr)
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(newReply)
            return
        }
    }

    sendError(w, "Post not found", http.StatusNotFound)
}

func generateReplyID(replies []Reply) int {
    maxID := 0
    for _, reply := range replies {
        if reply.ID > maxID {
            maxID = reply.ID
        }
    }
    return maxID + 1
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
    postID, err := strconv.Atoi(vars["postId"])
    if err != nil {
        log.Printf("Invalid post ID from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Invalid post ID", http.StatusBadRequest)
        return
    }
    commentID, err := strconv.Atoi(vars["commentId"])
    if err != nil {
        log.Printf("Invalid comment ID from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Invalid comment ID", http.StatusBadRequest)
        return
    }

    mutex.Lock()
    defer mutex.Unlock()

    for i, post := range posts {
        if post.ID == postID {
            for j, comment := range post.Comments {
                if comment.ID == commentID {
                    posts[i].Comments = append(post.Comments[:j], post.Comments[j+1:]...)
                    savePost(posts[i])
                    log.Printf("Comment %d deleted from post %d by admin %s from IP: %s", commentID, postID, username, r.RemoteAddr)
                    w.WriteHeader(http.StatusOK)
                    fmt.Fprintf(w, "Comment %d deleted from post %d", commentID, postID)
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
    postID, err := strconv.Atoi(vars["postId"])
    if err != nil {
        log.Printf("Invalid post ID from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Invalid post ID", http.StatusBadRequest)
        return
    }
    replyID, err := strconv.Atoi(vars["replyId"])
    if err != nil {
        log.Printf("Invalid reply ID from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Invalid reply ID", http.StatusBadRequest)
        return
    }

    mutex.Lock()
    defer mutex.Unlock()

    for i, post := range posts {
        if post.ID == postID {
            for j, reply := range post.Replies {
                if reply.ID == replyID {
                    posts[i].Replies = append(post.Replies[:j], post.Replies[j+1:]...)
                    savePost(posts[i])
                    log.Printf("Reply %d deleted from post %d by admin %s from IP: %s", replyID, postID, username, r.RemoteAddr)
                    w.WriteHeader(http.StatusOK)
                    fmt.Fprintf(w, "Reply %d deleted from post %d", replyID, postID)
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

    var user UserRequest
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        log.Printf("Error decoding JSON from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Error decoding JSON", http.StatusBadRequest)
        return
    }

    filePath := filepath.Join("users", user.Username+".user")
    if _, err := os.Stat(filePath); !os.IsNotExist(err) {
        log.Printf("User %s already exists, attempted from IP: %s", user.Username, r.RemoteAddr)
        sendError(w, "User already exists", http.StatusConflict)
        return
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        log.Printf("Error hashing password from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Error creating user", http.StatusInternalServerError)
        return
    }

    if err := os.MkdirAll("users", 0755); err != nil {
        log.Printf("Error creating users directory from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Error creating directory", http.StatusInternalServerError)
        return
    }
    if err := ioutil.WriteFile(filePath, hashedPassword, 0644); err != nil {
        log.Printf("Error saving user %s from IP: %s: %v", user.Username, r.RemoteAddr, err)
        sendError(w, "Error saving user", http.StatusInternalServerError)
        return
    }

    token := uuid.New().String()
    sessions[token] = Session{Username: user.Username, Token: token}

    http.SetCookie(w, &http.Cookie{
        Name:  "session_token",
        Value: token,
        Path:  "/",
    })
    log.Printf("User %s registered from IP: %s", user.Username, r.RemoteAddr)
    w.WriteHeader(http.StatusCreated)
    fmt.Fprintf(w, "User %s created successfully", user.Username)
}

func loginUser(w http.ResponseWriter, r *http.Request) {
    if !checkRateLimit(r.RemoteAddr) {
        log.Printf("Rate limit exceeded for IP: %s on loginUser", r.RemoteAddr)
        sendError(w, "Too many requests", http.StatusTooManyRequests)
        return
    }

    var user UserRequest
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        log.Printf("Error decoding JSON from IP: %s: %v", r.RemoteAddr, err)
        sendError(w, "Error decoding JSON", http.StatusBadRequest)
        return
    }

    if user.Username == adminUser && user.Password == adminPass {
        token := uuid.New().String()
        sessions[token] = Session{Username: adminUser, Token: token}
        http.SetCookie(w, &http.Cookie{
            Name:  "session_token",
            Value: token,
            Path:  "/",
        })
        log.Printf("Admin %s logged in from IP: %s", user.Username, r.RemoteAddr)
        w.WriteHeader(http.StatusOK)
        fmt.Fprintf(w, "Login successful for %s", user.Username)
        return
    }

    filePath := filepath.Join("users", user.Username+".user")
    hashedPassword, err := ioutil.ReadFile(filePath)
    if err != nil {
        log.Printf("Login failed - user %s not found from IP: %s", user.Username, r.RemoteAddr)
        sendError(w, "User not found", http.StatusNotFound)
        return
    }

    if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(user.Password)); err != nil {
        log.Printf("Login failed - incorrect password for %s from IP: %s", user.Username, r.RemoteAddr)
        sendError(w, "Incorrect password", http.StatusUnauthorized)
        return
    }

    token := uuid.New().String()
    sessions[token] = Session{Username: user.Username, Token: token}
    http.SetCookie(w, &http.Cookie{
        Name:  "session_token",
        Value: token,
        Path:  "/",
    })
    log.Printf("User %s logged in from IP: %s", user.Username, r.RemoteAddr)
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, "Login successful for %s", user.Username)
}

func logoutUser(w http.ResponseWriter, r *http.Request) {
    if !checkRateLimit(r.RemoteAddr) {
        log.Printf("Rate limit exceeded for IP: %s on logoutUser", r.RemoteAddr)
        sendError(w, "Too many requests", http.StatusTooManyRequests)
        return
    }

    token := r.Header.Get("X-Session-Token")
    if token != "" {
        username, _ := getUsernameFromToken(token)
        delete(sessions, token)
        log.Printf("User %s logged out from IP: %s", username, r.RemoteAddr)
    }
    http.SetCookie(w, &http.Cookie{
        Name:   "session_token",
        Value:  "",
        Path:   "/",
        MaxAge: -1,
    })
    w.WriteHeader(http.StatusOK)
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
    w.WriteHeader(http.StatusOK)
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
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, "IP %s banned", ip)
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
    router.HandleFunc("/posts/{postId}/comments/{commentId}/replies", addReply).Methods("POST")
    router.HandleFunc("/posts/{postId}/comments/{commentId}", deleteComment).Methods("DELETE")
    router.HandleFunc("/posts/{postId}/replies/{replyId}", deleteReply).Methods("DELETE")
    router.HandleFunc("/register", registerUser).Methods("POST")
    router.HandleFunc("/login", loginUser).Methods("POST")
    router.HandleFunc("/logout", logoutUser).Methods("POST")
    router.HandleFunc("/ban/user/{username}", banUser).Methods("POST")
    router.HandleFunc("/ban/ip/{ip}", banIP).Methods("POST")

    router.PathPrefix("/").Handler(http.FileServer(http.Dir("./public")))

    fmt.Println("Server running at https://localhost:443 (or http://localhost:3000 if certs missing)")
    err := http.ListenAndServeTLS(":443", "cert.pem", "key.pem", router)
    if err != nil {
        log.Printf("TLS failed, falling back to HTTP: %v", err)
        log.Fatal(http.ListenAndServe(":3000", router))
    }
}