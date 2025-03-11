package main

import (
	"crypto/x509"
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

	// 証明書の解析
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}
	fmt.Println(cert)

	// Subject DNの取得
	subjectDN := cert.Subject.String()
	fmt.Printf("Subject DN: %s\n", subjectDN)

	// SANの取得
	for _, san := range cert.DNSNames {
		fmt.Printf("SAN: %s\n", san)
	}
}
