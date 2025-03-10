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

func main() {
	go func() {
		http.HandleFunc("/upstream/", upstreamHandler)
		log.Println("Upstream server is running on port 8081")
		log.Fatal(http.ListenAndServe(":8081", nil))
	}()

	http.Handle("/", clientCertMiddleware(http.HandlerFunc(proxyhandler)))
	log.Println("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func clientCertMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.Header)
		// 証明書の抽出
		certHeader := r.Header.Get("X-SSL-Client-Cert")
		fmt.Printf("certificate: %s\n", certHeader)
		if certHeader == "" {
			http.Error(w, "Client certificate not found", http.StatusForbidden)
			return
		}

		// 証明書のデコード
		decodedCertHeader, err := base64.StdEncoding.DecodeString(certHeader)
		if err != nil {
			http.Error(w, "Failed to decode certificate", http.StatusForbidden)
			return
		}
		fmt.Printf("decodedCertHeader: %s\n", decodedCertHeader)
		certBlock, _ := pem.Decode([]byte(decodedCertHeader))
		fmt.Printf("certBlock: %s\n", certBlock)
		if certBlock == nil {
			http.Error(w, "Failed to decode certificate", http.StatusForbidden)
			return
		}

		// 証明書の解析
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			http.Error(w, "Failed to parse certificate", http.StatusForbidden)
			return
		}

		// ファイルからルート証明書を読み込む
		rootCertPEM, err := os.ReadFile("pki/rootCA.crt")
		if err != nil {
			http.Error(w, "Failed to read root certificate", http.StatusForbidden)
			return
		}

		// ルート証明書をCertPoolに追加
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(rootCertPEM) {
			http.Error(w, "Failed to add root certificate to CertPool", http.StatusForbidden)
			return
		}

		// 証明書の検証
		opts := x509.VerifyOptions{
			Roots: roots,
		}
		if _, err := cert.Verify(opts); err != nil {
			http.Error(w, "Failed to verify certificate", http.StatusForbidden)
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
	for _, v := range r.Header {
		fmt.Println(v)
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
