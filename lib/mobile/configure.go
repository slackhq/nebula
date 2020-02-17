package mobileNebula

import (
    "fmt"
    "net/http"
)

var msg := "empty"

func ConfigHTTPServer() {
    fmt.Println("webserver start")
    http.HandleFunc("/", HelloServer)
    http.ListenAndServe(":8080", nil)
}

func HelloServer(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Howdy, %s\n%s!", r.RemoteAddr, msg)
}

func SetMessage(m string) {
	msg = m
}
