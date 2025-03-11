package main

import (
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func main() {
	clientCert, _ := os.ReadFile("pki/client.crt")
	if clientCert == nil {
		log.Fatal("Client certificate not found")
	}
	fmt.Println("clientCert:", clientCert)
	certBlock, _ := pem.Decode(clientCert)
	if certBlock == nil {
		log.Fatal("Failed to decode certificate")
	}
	fmt.Println("certBlock:", certBlock)
}
