package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type CertManager interface {
	LoadRootCert() (*x509.CertPool, error)
	VerifyCert(certPEM string) (*x509.Certificate, error)
}

type FileCertManager struct {
	rootCertPath string
}

func (f *FileCertManager) LoadRootCert() (*x509.CertPool, error) {
	// ローカルからルート証明書を読み込み
	rootCertPEM, err := os.ReadFile(f.rootCertPath)
	if err != nil {
		return nil, err
	}

	// ルート証明書をCertPoolに追加
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootCertPEM) {
		return nil, fmt.Errorf("failed to add root certificate to CertPool")
	}

	return roots, nil
}

func (f *FileCertManager) VerifyCert(certPEM string) (*x509.Certificate, error) {
	decodedCertHeader, err := base64.StdEncoding.DecodeString(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}

	certBlock, _ := pem.Decode(decodedCertHeader)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate")
	}

	return cert, nil
}

func main() {
	certManager := &FileCertManager{rootCertPath: "pki/rootCA.crt"}

	go func() {
		http.HandleFunc("/upstream/", upstreamHandler)
		log.Println("Upstream server is running on port 8081")
		log.Fatal(http.ListenAndServe(":8081", nil))
	}()

	http.Handle("/", clientCertMiddleware(http.HandlerFunc(proxyhandler), certManager))
	log.Println("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func clientCertMiddleware(next http.Handler, certManager CertManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.Header)
		// 証明書の抽出
		certHeader := r.Header.Get("X-SSL-Client-Cert")
		fmt.Printf("certificate: %s\n", certHeader)
		if certHeader == "" {
			http.Error(w, "Client certificate not found", http.StatusForbidden)
			return
		}

		cert, err := certManager.VerifyCert(certHeader)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		roots, err := certManager.LoadRootCert()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError) 
		}

		opts := x509.VerifyOptions{
			Roots: roots,
		}

		if _, err := cert.Verify(opts); err != nil {
			http.Error(w, "Fail to verify certificate", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func proxyhandler(w http.ResponseWriter, r *http.Request) {
	// プロキシリクエストの作成
	proxyURL := "http://localhost:8081/upstream/" // アップストリーミングサーバのURL
	proxyReq, err := http.NewRequest(r.Method, proxyURL, r.Body)
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}
	proxyReq.Header = r.Header
	for k, v := range r.Header {
		fmt.Println(k, v)
	}

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Failed to send proxy request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	for k, v := range resp.Header {
		for _, h := range v {
			w.Header().Add(k, h)
		}
	}

	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func upstreamHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello from upstream server"))
}
