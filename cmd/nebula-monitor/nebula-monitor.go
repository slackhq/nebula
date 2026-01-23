package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func handlePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Print to console
	//fmt.Printf("Path: %s\n", r.URL.Path)
	//fmt.Printf("Headers: %v\n", r.Header)
	fmt.Printf("%s\n", string(body))

	// Send response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
}

func main() {
	http.HandleFunc("/", handlePost)

	fmt.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
