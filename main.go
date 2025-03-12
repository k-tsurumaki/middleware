package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type certManager interface {
	loadRootCert() (*x509.CertPool, error)                                     // ローカルからルート証明書を読み込む関数
	verifyCert(certHeader string) (*x509.Certificate, error)                      // リクエストヘッダに含まれるクライアント証明書のフォーマットを修正する関数
	isFingerprintMatched(cert *x509.Certificate, fingerprintHeader string) bool // フィンガープリントを検証する関数

}

type fileCertManager struct {
	rootCertPath string // ルート証明書のパス
}

func (f *fileCertManager) loadRootCert() (*x509.CertPool, error) {
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

func (f *fileCertManager) verifyCert(certHeader string) (*x509.Certificate, error) {
	// base64でエンコードされている文字列のクライアント証明書をデコードし、バイト列に変換
	decodedCertHeader, err := base64.StdEncoding.DecodeString(certHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}

	// バイト列に変換したクライアント証明書をPEMブロックに変換
	certBlock, _ := pem.Decode(decodedCertHeader)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}

	// PRMブロックを解析
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate")
	}

	return cert, nil
}

func (f *fileCertManager) isFingerprintMatched(cert *x509.Certificate, fingerprintHeader string) bool {
	fingerprint := sha256.Sum256(cert.Raw)
	fmt.Println(":::fingerprint:::")
	fmt.Println(hex.EncodeToString(fingerprint[:]))
	return hex.EncodeToString(fingerprint[:]) == fingerprintHeader
}

func isCertExpired(cert *x509.Certificate) bool {
	fmt.Println(":::expiration date:::")
	fmt.Println(cert.NotAfter)
	return time.Now().After(cert.NotAfter)
}

func clientCertMiddleware(next http.Handler, certManager certManager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r.Header)

		// 証明書の抽出
		certHeader := r.Header.Get("X-SSL-Client-Cert")
		fmt.Printf("certificate: %s\n", certHeader)
		if certHeader == "" {
			http.Error(w, "Client certificate not found", http.StatusForbidden)
			return
		}

		// フィンガープリントの抽出
		fingerprintHeader := r.Header.Get("X-SSL-Client-Fingerprint")
		fmt.Printf("fingerprint: %s\n", fingerprintHeader)
		if certHeader == "" {
			http.Error(w, "Fingerprint is not found", http.StatusForbidden)
			return
		}

		cert, err := certManager.verifyCert(certHeader)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Println(":::certificate:::")
		fmt.Println(cert)

		roots, err := certManager.loadRootCert()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		opts := x509.VerifyOptions{
			Roots: roots,
		}

		// クライアント証明書の検証
		if _, err := cert.Verify(opts); err != nil {
			http.Error(w, "Fail to verify certificate", http.StatusForbidden)
			return
		}

		// フィンガープリントの検証
		if !certManager.isFingerprintMatched(cert, fingerprintHeader) {
			http.Error(w, "Fail to verify fingerprint", http.StatusForbidden)
			return
		}

		// 有効期限の確認
		if isCertExpired(cert) {
			http.Error(w, "Certificate has expired", http.StatusForbidden)
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

func main() {
	certManager := &fileCertManager{rootCertPath: "pki/rootCA.crt"}

	go func() {
		http.HandleFunc("/upstream/", upstreamHandler)
		log.Println("Upstream server is running on port 8081")
		log.Fatal(http.ListenAndServe(":8081", nil))
	}()

	http.Handle("/", clientCertMiddleware(http.HandlerFunc(proxyhandler), certManager))
	log.Println("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
