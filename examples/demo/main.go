package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

type countHandler struct {
	mu sync.Mutex // guards n
	n  int
}

func (h *countHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.n++
	time.Sleep(100 * time.Millisecond)
	log.Printf("count is %d\n", h.n)
	fmt.Fprintf(w, "count is %d\n", h.n)
	fmt.Fprintf(w, "Content Size: %d\n", r.ContentLength)
	fmt.Fprintf(w, "Version: %d.%d\n", r.ProtoMajor, r.ProtoMinor)
}

func main() {
	log.Println("Starting server on :8080")
	http.Handle("/count", new(countHandler))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
