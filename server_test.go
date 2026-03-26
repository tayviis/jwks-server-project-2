package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// setup runs BEFORE each test safely
func setup() {
	if db == nil {
		db = initDB()
	}
	seedKeys()

	http.DefaultServeMux = new(http.ServeMux)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
}

func TestJWKS(t *testing.T) {
	setup()

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	http.DefaultServeMux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

func TestAuth(t *testing.T) {
	setup()

	req := httptest.NewRequest("POST", "/auth", nil)
	w := httptest.NewRecorder()

	http.DefaultServeMux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}

func TestAuthExpired(t *testing.T) {
	setup()

	req := httptest.NewRequest("POST", "/auth?expired=true", nil)
	w := httptest.NewRecorder()

	http.DefaultServeMux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 got %d", w.Code)
	}
}
