package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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

	// PRMブロックを解析
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Fatal("Failed to decode certificate")
	}

	fingerprint := sha256.Sum256(cert.Raw)
	fmt.Println(fingerprint)
	fingerprintHex := hex.EncodeToString(fingerprint[:])
	fmt.Println(fingerprintHex)

}
