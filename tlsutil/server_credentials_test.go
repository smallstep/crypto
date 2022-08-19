package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"go.step.sm/crypto/x509util"
)

func testServerRenewFunc(hello *tls.ClientHelloInfo) (*tls.Certificate, *tls.Config, error) {
	var err error
	leafCert.NotBefore = time.Now()
	leafCert.DNSNames, leafCert.IPAddresses, leafCert.EmailAddresses, leafCert.URIs = x509util.SplitSANs([]string{hello.ServerName})
	leafCert.NotAfter = leafCert.NotBefore.Add(time.Hour)
	leafCert.SerialNumber = leafCert.SerialNumber.Add(leafCert.SerialNumber, big.NewInt(1))
	leafCert, err = x509util.CreateCertificate(leafCert, issuerCert, leafKey.Public(), issuerKey)
	if err != nil {
		return nil, nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{leafCert.Raw},
		PrivateKey:  leafKey,
		Leaf:        leafCert,
	}, tlsConfig, nil
}

func TestNewServerCredentials(t *testing.T) {
	type args struct {
		fn ServerRenewFunc
	}
	tests := []struct {
		name    string
		args    args
		want    *ServerCredentials
		wantErr bool
	}{
		{"ok", args{testServerRenewFunc}, &ServerCredentials{RenewFunc: testServerRenewFunc, cache: newCredentialsCache()}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewServerCredentials(tt.args.fn)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewServerCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// Cannot deep equal methods
			if got != nil {
				got.RenewFunc = nil
			}
			if tt.want != nil {
				tt.want.RenewFunc = nil
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewServerCredentials() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewServerCredentialsFromFile(t *testing.T) {
	dir := t.TempDir()

	certFile := filepath.Join(dir, "testcert.crt")
	keyFile := filepath.Join(dir, "testcert.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	}), 0600); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}), 0600); err != nil {
		t.Fatal(err)
	}

	type args struct {
		certFile string
		keyFile  string
	}
	tests := []struct {
		name     string
		args     args
		wantCert *tls.Certificate
		wantErr  bool
	}{
		{"ok", args{certFile, keyFile}, &tls.Certificate{
			Certificate: [][]byte{leafCert.Raw},
			PrivateKey:  leafKey,
			Leaf:        leafCert,
		}, false},
		{"fail", args{certFile, filepath.Join(dir, "missing.key")}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewServerCredentialsFromFile(tt.args.certFile, tt.args.keyFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewServerCredentialsFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantCert != nil {
				cert, err := got.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
				if err != nil {
					t.Errorf("GetCertificate() error = %v", err)
					return
				}
				if !reflect.DeepEqual(cert, tt.wantCert) {
					t.Errorf("GetCertificate() = \n%v, want \n%v", cert, tt.wantCert)
				}
			}
		})
	}
}

func TestServerCredentials_GetCertificate(t *testing.T) {
	// Prepare server
	sc, err := NewServerCredentials(testServerRenewFunc)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	}))
	srv.TLS = &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: sc.GetCertificate,
	}
	srv.StartTLS()
	// We need to set Certificates to nil, because if the hello message does not
	// have a SNI, this certificate will be used.
	srv.TLS.Certificates = nil
	defer srv.Close()

	// Create url with localhost
	dnsURL := getLocalHostURL(t, srv.URL)

	// Prepare valid client
	pool := x509.NewCertPool()
	pool.AddCert(issuerCert)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}

	tests := []struct {
		name    string
		client  *http.Client
		url     string
		want    []byte
		wantErr bool
	}{
		{"ok", &http.Client{Transport: tr}, dnsURL, []byte("ok"), false},
		{"fail empty", &http.Client{}, dnsURL, nil, true},
		{"fail httptest", srv.Client(), dnsURL, nil, true},
		{"fail ip", &http.Client{Transport: tr}, srv.URL, nil, true},
		{"fail httptest ip", srv.Client(), srv.URL, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.client.Get(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("http.Client.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if resp != nil && resp.Body != nil {
				got, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Errorf("io.ReadAll() error = %v", err)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("http.Client.Get() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestServerCredentials_GetConfigForClient(t *testing.T) {
	// Prepare server
	sc, err := NewServerCredentials(testServerRenewFunc)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	}))
	srv.TLS = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		GetConfigForClient: sc.GetConfigForClient,
	}
	srv.StartTLS()
	// We need to set Certificates to nil, because if the hello message does not
	// have a SNI, this certificate will be used.
	srv.TLS.Certificates = nil
	defer srv.Close()

	// Create url with localhost
	dnsURL := getLocalHostURL(t, srv.URL)

	// Prepare valid client
	pool := x509.NewCertPool()
	pool.AddCert(issuerCert)

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}

	tests := []struct {
		name    string
		client  *http.Client
		url     string
		want    []byte
		wantErr bool
	}{
		{"ok", &http.Client{Transport: tr}, dnsURL, []byte("ok"), false},
		{"fail empty", &http.Client{}, dnsURL, nil, true},
		{"fail httptest", srv.Client(), dnsURL, nil, true},
		{"fail ip", &http.Client{Transport: tr}, srv.URL, nil, true},
		{"fail httptest ip", srv.Client(), srv.URL, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.client.Get(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("http.Client.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if resp != nil && resp.Body != nil {
				got, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Errorf("io.ReadAll() error = %v", err)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("http.Client.Get() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestServerCredentials_RenewFunc_error(t *testing.T) {
	// Prepare server
	sc, err := NewServerCredentials(func(hello *tls.ClientHelloInfo) (*tls.Certificate, *tls.Config, error) {
		return nil, nil, fmt.Errorf("test error")
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		tlsConfig *tls.Config
	}{
		{"fail GetCertificate", &tls.Config{GetCertificate: sc.GetCertificate, MinVersion: tls.VersionTLS12}},
		{"fail GetConfigForClient", &tls.Config{GetConfigForClient: sc.GetConfigForClient, MinVersion: tls.VersionTLS12}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "ok")
			}))
			srv.TLS = tt.tlsConfig
			srv.StartTLS()
			defer srv.Close()

			// Prepare valid client
			pool := x509.NewCertPool()
			pool.AddCert(issuerCert)

			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.TLSClientConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			}

			c := &http.Client{Transport: tr}
			if _, err := c.Get(getLocalHostURL(t, srv.URL)); err == nil {
				t.Errorf("http.Client.Get() error = %v, wantErr true", err)
			}
		})
	}
}

func TestServerCredentials_TLSConfig(t *testing.T) {
	sc, err := NewServerCredentials(testServerRenewFunc)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name              string
		serverCredentials *ServerCredentials
		want              *tls.Config
	}{
		{"ok", sc, &tls.Config{
			MinVersion:         tls.VersionTLS12,
			GetCertificate:     sc.GetCertificate,
			GetConfigForClient: sc.GetConfigForClient,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.serverCredentials.TLSConfig()
			if got.GetCertificate == nil || got.GetConfigForClient == nil {
				t.Errorf("ServerCredentials.TLSConfig() = \n%#v, want \n%#v", got, tt.want)
			}
		})
	}
}
