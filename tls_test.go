package cryptopasta

import (
	"log"
	"net/http"
)

func ExampleTLSServer() {
	// Get recommended basic configuration
	config := DefaultTLSConfig()

	// Serve up some HTTP
	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("Hello, world\n"))
	})

	server := &http.Server{
		Addr:      ":8080",
		TLSConfig: config,
	}

	err := server.ListenAndServeTLS("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
}
