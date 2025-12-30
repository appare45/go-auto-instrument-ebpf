package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

func setupTestServer(t *testing.T) *Server {
	t.Helper()

	tmpFile := "test_demo.db"
	os.Remove(tmpFile)

	db, err := sql.Open("sqlite", tmpFile)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	server := &Server{db: db}

	if err := server.initDB(); err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
		os.Remove(tmpFile)
	})

	return server
}

func TestHealthEndpoint(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", response["status"])
	}
}

func TestCreateItem(t *testing.T) {
	server := setupTestServer(t)

	reqBody := `{"value": "test item"}`
	req := httptest.NewRequest(http.MethodPost, "/items", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleItems(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", w.Code)
	}

	var item Item
	if err := json.NewDecoder(w.Body).Decode(&item); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if item.ID != 1 {
		t.Errorf("Expected ID 1, got %d", item.ID)
	}

	if item.Value != "test item" {
		t.Errorf("Expected value 'test item', got '%s'", item.Value)
	}
}

func TestCreateItemEmptyValue(t *testing.T) {
	server := setupTestServer(t)

	reqBody := `{"value": ""}`
	req := httptest.NewRequest(http.MethodPost, "/items", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleItems(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["error"] != "value cannot be empty" {
		t.Errorf("Expected error message 'value cannot be empty', got '%s'", response["error"])
	}
}

func TestCreateItemInvalidJSON(t *testing.T) {
	server := setupTestServer(t)

	reqBody := `{"value": invalid}`
	req := httptest.NewRequest(http.MethodPost, "/items", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleItems(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestGetAllItems(t *testing.T) {
	server := setupTestServer(t)

	server.db.Exec("INSERT INTO items (value) VALUES (?)", "item 1")
	server.db.Exec("INSERT INTO items (value) VALUES (?)", "item 2")

	req := httptest.NewRequest(http.MethodGet, "/items", nil)
	w := httptest.NewRecorder()

	server.handleItems(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var items []Item
	if err := json.NewDecoder(w.Body).Decode(&items); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(items) != 2 {
		t.Errorf("Expected 2 items, got %d", len(items))
	}

	if items[0].Value != "item 1" || items[1].Value != "item 2" {
		t.Errorf("Items values don't match expected values")
	}
}

func TestGetAllItemsEmpty(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/items", nil)
	w := httptest.NewRecorder()

	server.handleItems(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var items []Item
	if err := json.NewDecoder(w.Body).Decode(&items); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if len(items) != 0 {
		t.Errorf("Expected 0 items, got %d", len(items))
	}
}

func TestGetItemByID(t *testing.T) {
	server := setupTestServer(t)

	server.db.Exec("INSERT INTO items (value) VALUES (?)", "test item")

	req := httptest.NewRequest(http.MethodGet, "/items/1", nil)
	w := httptest.NewRecorder()

	server.handleGetItem(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var item Item
	if err := json.NewDecoder(w.Body).Decode(&item); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if item.ID != 1 || item.Value != "test item" {
		t.Errorf("Item doesn't match expected values")
	}
}

func TestGetItemByIDNotFound(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/items/999", nil)
	w := httptest.NewRecorder()

	server.handleGetItem(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["error"] != "Item not found" {
		t.Errorf("Expected error message 'Item not found', got '%s'", response["error"])
	}
}

func TestGetItemByIDInvalidFormat(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/items/abc", nil)
	w := httptest.NewRecorder()

	server.handleGetItem(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["error"] != "Invalid ID format" {
		t.Errorf("Expected error message 'Invalid ID format', got '%s'", response["error"])
	}
}

func TestMethodNotAllowed(t *testing.T) {
	server := setupTestServer(t)

	tests := []struct {
		name     string
		method   string
		path     string
		handler  http.HandlerFunc
	}{
		{"DELETE on /items", http.MethodDelete, "/items", server.handleItems},
		{"PUT on /items", http.MethodPut, "/items", server.handleItems},
		{"POST on /health", http.MethodPost, "/health", server.handleHealth},
		{"POST on /items/1", http.MethodPost, "/items/1", server.handleGetItem},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			tt.handler(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status 405, got %d", w.Code)
			}
		})
	}
}
