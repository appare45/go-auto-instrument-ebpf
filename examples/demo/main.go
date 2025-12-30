package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

type Item struct {
	ID    int    `json:"id"`
	Value string `json:"value"`
}

type CreateItemRequest struct {
	Value string `json:"value"`
}

type Server struct {
	db *sql.DB
}

func (s *Server) initDB() error {
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		value TEXT NOT NULL
	);`

	_, err := s.db.Exec(createTableQuery)
	if err != nil {
		return err
	}

	log.Println("Database initialized successfully")
	return nil
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON: %v", err)
	}
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}

func (s *Server) handleItems(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleCreateItem(w, r)
	case http.MethodGet:
		s.handleGetAllItems(w, r)
	default:
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleCreateItem(w http.ResponseWriter, r *http.Request) {
	var req CreateItemRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if strings.TrimSpace(req.Value) == "" {
		respondError(w, http.StatusBadRequest, "value cannot be empty")
		return
	}

	result, err := s.db.Exec("INSERT INTO items (value) VALUES (?)", req.Value)
	if err != nil {
		log.Printf("Error inserting item: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to create item")
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		log.Printf("Error getting last insert ID: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to get item ID")
		return
	}

	item := Item{
		ID:    int(id),
		Value: req.Value,
	}

	log.Printf("Created item: id=%d, value=%s", item.ID, item.Value)
	respondJSON(w, http.StatusCreated, item)
}

func (s *Server) handleGetAllItems(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query("SELECT id, value FROM items ORDER BY id")
	if err != nil {
		log.Printf("Error querying items: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to get items")
		return
	}
	defer rows.Close()

	items := []Item{}
	for rows.Next() {
		var item Item
		if err := rows.Scan(&item.ID, &item.Value); err != nil {
			log.Printf("Error scanning row: %v", err)
			respondError(w, http.StatusInternalServerError, "Failed to scan items")
			return
		}
		items = append(items, item)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating rows: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to process items")
		return
	}

	log.Printf("Retrieved %d items", len(items))
	respondJSON(w, http.StatusOK, items)
}

func (s *Server) handleGetItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/items/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid ID format")
		return
	}

	var item Item
	err = s.db.QueryRow("SELECT id, value FROM items WHERE id = ?", id).Scan(&item.ID, &item.Value)
	if err == sql.ErrNoRows {
		respondError(w, http.StatusNotFound, "Item not found")
		return
	} else if err != nil {
		log.Printf("Error querying item: %v", err)
		respondError(w, http.StatusInternalServerError, "Failed to get item")
		return
	}

	log.Printf("Retrieved item: id=%d, value=%s", item.ID, item.Value)
	respondJSON(w, http.StatusOK, item)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if err := s.db.Ping(); err != nil {
		log.Printf("Database ping failed: %v", err)
		respondError(w, http.StatusServiceUnavailable, "Database unavailable")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func main() {
	db, err := sql.Open("sqlite", "demo.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	server := &Server{db: db}

	if err := server.initDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "index.html")
		} else {
			http.NotFound(w, r)
		}
	})
	http.HandleFunc("/items", server.handleItems)
	http.HandleFunc("/items/", server.handleGetItem)
	http.HandleFunc("/health", server.handleHealth)

	log.Println("Starting server on :8080")
	log.Println("Open http://localhost:8080 in your browser")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
