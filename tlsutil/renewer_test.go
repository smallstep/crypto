package tlsutil

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"
)

var (
	issuerCert *x509.Certificate
	issuerKey  crypto.Signer
	leafCsr    *x509.CertificateRequest
	leafCert   *x509.Certificate
	leafKey    crypto.Signer
	tlsCert    *tls.Certificate
	tlsConfig  *tls.Config
)

func TestMain(m *testing.M) {
	var err error
	// Create Issuer
	issuerKey, err = keyutil.GenerateDefaultSigner()
	if err != nil {
		panic(err)
	}
	issuerCsr, err := x509util.CreateCertificateRequest("RootCA", []string{}, issuerKey)
	if err != nil {
		panic(err)
	}
	cert, err := x509util.NewCertificate(issuerCsr,
		x509util.WithTemplate(x509util.DefaultRootTemplate, x509util.CreateTemplateData("RootCA", []string{})))
	if err != nil {
		panic(err)
	}
	parent := cert.GetCertificate()
	parent.NotBefore = time.Now()
	parent.NotAfter = parent.NotBefore.Add(time.Hour)
	issuerCert, err = x509util.CreateCertificate(parent, parent, issuerKey.Public(), issuerKey)
	if err != nil {
		panic(err)
	}

	// Create Leaf
	leafKey, err = keyutil.GenerateDefaultSigner()
	if err != nil {
		panic(err)
	}
	leafCsr, err = x509util.CreateCertificateRequest("Leaf", []string{"127.0.0.1", "localhost"}, leafKey)
	if err != nil {
		panic(err)
	}
	cert, err = x509util.NewCertificate(leafCsr,
		x509util.WithTemplate(x509util.DefaultLeafTemplate, x509util.CreateTemplateData("Leaf", []string{"127.0.0.1", "localhost"})))
	if err != nil {
		panic(err)
	}
	template := cert.GetCertificate()
	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(time.Hour)
	template.SerialNumber = big.NewInt(1)
	leafCert, err = x509util.CreateCertificate(template, issuerCert, leafKey.Public(), issuerKey)
	if err != nil {
		panic(err)
	}

	// Create tls cert and config
	pool := x509.NewCertPool()
	pool.AddCert(issuerCert)
	tlsCert = &tls.Certificate{
		Certificate: [][]byte{leafCert.Raw},
		PrivateKey:  leafKey,
		Leaf:        leafCert,
	}
	tlsConfig = &tls.Config{
		RootCAs:    pool,
		ClientCAs:  pool,
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS12,
	}

	os.Exit(m.Run())
}

func testRenewFunc() (*tls.Certificate, *tls.Config, error) {
	cert, err := x509util.NewCertificate(leafCsr,
		x509util.WithTemplate(x509util.DefaultLeafTemplate, x509util.CreateTemplateData("Leaf", []string{"127.0.0.1", "localhost"})))
	if err != nil {
		return nil, nil, err
	}
	template := cert.GetCertificate()
	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(time.Hour)
	template.SerialNumber = big.NewInt(1)
	leaf, err := x509util.CreateCertificate(template, issuerCert, leafKey.Public(), issuerKey)
	if err != nil {
		return nil, nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{leafCert.Raw},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}, tlsConfig, nil
}

func getLocalHostURL(t *testing.T, rawurl string) string {
	t.Helper()

	u, err := url.Parse(rawurl)
	if err != nil {
		t.Fatal(err)
	}
	_, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	return "https://" + net.JoinHostPort("localhost", p)
}

func TestNewRenewer(t *testing.T) {
	now := time.Now()
	type args struct {
		cert   *tls.Certificate
		config *tls.Config
		fn     RenewFunc
		opts   []renewerOptions
	}
	tests := []struct {
		name    string
		args    args
		want    *Renewer
		wantErr bool
	}{
		{"ok", args{tlsCert, tlsConfig, testRenewFunc, nil}, &Renewer{
			RenewFunc:    testRenewFunc,
			cert:         tlsCert,
			config:       tlsConfig.Clone(),
			renewBefore:  time.Hour / 3,
			renewJitter:  time.Hour / 20,
			certNotAfter: leafCert.NotAfter,
		}, false},
		{"WithRenewBefore", args{tlsCert, tlsConfig, testRenewFunc, []renewerOptions{WithRenewBefore(time.Minute)}}, &Renewer{
			RenewFunc:    testRenewFunc,
			cert:         tlsCert,
			config:       tlsConfig.Clone(),
			renewBefore:  time.Minute,
			renewJitter:  time.Hour / 20,
			certNotAfter: leafCert.NotAfter,
		}, false},
		{"WithRenewJitter", args{tlsCert, tlsConfig, testRenewFunc, []renewerOptions{WithRenewJitter(time.Minute)}}, &Renewer{
			RenewFunc:    testRenewFunc,
			cert:         tlsCert,
			config:       tlsConfig.Clone(),
			renewBefore:  time.Hour / 3,
			renewJitter:  time.Minute,
			certNotAfter: leafCert.NotAfter,
		}, false},
		{"fail", args{&tls.Certificate{
			Certificate: [][]byte{leafCert.Raw},
			PrivateKey:  leafKey,
			Leaf: &x509.Certificate{
				NotBefore: now,
				NotAfter:  now.Add(MinCertDuration - time.Nanosecond),
			},
		}, tlsConfig, testRenewFunc, []renewerOptions{WithRenewJitter(time.Minute)}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRenewer(tt.args.cert, tt.args.config, tt.args.fn, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRenewer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Cannot deep equal methods
			if got != nil {
				got.RenewFunc = nil
				got.config.GetCertificate = nil
				got.config.GetClientCertificate = nil
				got.config.GetConfigForClient = nil
			}
			if tt.want != nil {
				tt.want.RenewFunc = nil
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRenewer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRenewer_Run(t *testing.T) {
	var i int32
	fn := func() (*tls.Certificate, *tls.Config, error) {
		atomic.AddInt32(&i, 1)
		return testRenewFunc()
	}

	r, err := NewRenewer(tlsCert, tlsConfig, fn)
	if err != nil {
		t.Fatal(err)
	}
	r.renewJitter = 1
	r.renewBefore = time.Until(tlsCert.Leaf.NotAfter) - time.Second

	r.Run()
	defer r.Stop()

	time.Sleep(2 * time.Second)
	if ii := atomic.LoadInt32(&i); ii == 0 {
		t.Errorf("Renewer.Run() timer didn't run")
	} else {
		t.Logf("Renewer.Run() run %d times", ii)
	}
}

func TestRenewer_RunContext(t *testing.T) {
	var i int32
	fn := func() (*tls.Certificate, *tls.Config, error) {
		atomic.AddInt32(&i, 1)
		return testRenewFunc()
	}

	r, err := NewRenewer(tlsCert, tlsConfig, fn)
	if err != nil {
		t.Fatal(err)
	}
	r.renewJitter = 1
	r.renewBefore = time.Until(tlsCert.Leaf.NotAfter) - time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r.RunContext(ctx)

	time.Sleep(2 * time.Second)
	if ii := atomic.LoadInt32(&i); ii == 0 {
		t.Errorf("Renewer.RunContext() timer didn't run")
	} else {
		t.Logf("Renewer.RunContext() run %d times", ii)
	}
}

func TestRenewer_Stop(t *testing.T) {
	type fields struct {
		timer *time.Timer
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{"ok", fields{time.AfterFunc(time.Second, func() {})}, true},
		{"ok nil", fields{nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Renewer{
				timer: tt.fields.timer,
			}
			if got := r.Stop(); got != tt.want {
				t.Errorf("Renewer.Stop() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRenewer_GetCertificate(t *testing.T) {
	// Prepare server
	r, err := NewRenewer(tlsCert, tlsConfig, testRenewFunc)
	if err != nil {
		t.Fatal(err)
	}
	r.Run()
	defer r.Stop()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	}))
	srv.TLS = r.GetConfig()
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

	tests := []struct {
		name    string
		client  *http.Client
		want    []byte
		wantErr bool
	}{
		{"ok", &http.Client{Transport: tr}, []byte("ok"), false},
		{"fail empty", &http.Client{}, nil, true},
		{"fail httptest", srv.Client(), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.client.Get(srv.URL)
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

func TestRenewer_GetClientCertificate(t *testing.T) {
	// Prepare server
	r, err := NewRenewer(tlsCert, tlsConfig, testRenewFunc)
	if err != nil {
		t.Fatal(err)
	}
	r.Run()
	defer r.Stop()

	pool := x509.NewCertPool()
	pool.AddCert(issuerCert)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			t.Error("missing peer certificate")
		}
		fmt.Fprintf(w, "ok")
	}))
	srv.TLS = &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: r.GetCertificate,
		ClientCAs:      pool,
		ClientAuth:     tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	// We need to set Certificates to nil, because if the hello message does not
	// have a SNI, this certificate will be used.
	srv.TLS.Certificates = nil
	defer srv.Close()

	// Prepare valid client
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		MinVersion:           tls.VersionTLS12,
		GetClientCertificate: r.GetClientCertificate,
		RootCAs:              pool,
	}

	trNoCert := http.DefaultTransport.(*http.Transport).Clone()
	trNoCert.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}

	tests := []struct {
		name    string
		client  *http.Client
		want    []byte
		wantErr bool
	}{
		{"ok", &http.Client{Transport: tr}, []byte("ok"), false},
		{"fail no cert", &http.Client{Transport: trNoCert}, nil, true},
		{"fail empty", &http.Client{}, nil, true},
		{"fail httptest", srv.Client(), nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := tt.client.Get(srv.URL)
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

func TestRenewer_RenewFunc_error(t *testing.T) {
	// Create exprired cert
	leafCsr, err := x509util.CreateCertificateRequest("Leaf", []string{"127.0.0.1", "localhost"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509util.NewCertificate(leafCsr,
		x509util.WithTemplate(x509util.DefaultLeafTemplate, x509util.CreateTemplateData("Leaf", []string{"127.0.0.1", "localhost"})))
	if err != nil {
		t.Fatal(err)
	}
	template := cert.GetCertificate()
	template.NotBefore = time.Now()
	template.NotAfter = time.Now()
	template.SerialNumber = big.NewInt(1)
	leaf, err := x509util.CreateCertificate(template, issuerCert, leafKey.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	expiredCert := &tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}

	// Prepare server
	r, err := NewRenewer(tlsCert, tlsConfig, func() (*tls.Certificate, *tls.Config, error) {
		return nil, nil, fmt.Errorf("test error")
	})
	if err != nil {
		t.Fatal(err)
	}
	r.Run()
	defer r.Stop()

	// Mark certificate as expired
	r.Lock()
	r.cert = expiredCert
	r.certNotAfter = expiredCert.Leaf.NotAfter
	r.Unlock()

	pool := x509.NewCertPool()
	pool.AddCert(issuerCert)

	tests := []struct {
		name         string
		serverConfig *tls.Config
		clientConfig *tls.Config
	}{
		{"fail GetCertificate", &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: r.GetCertificate,
			ClientAuth:     tls.RequireAndVerifyClientCert,
			ClientCAs:      pool,
		}, &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return tlsCert, nil
			},
			RootCAs: pool,
		}},
		{"fail GetConfigForClient", &tls.Config{
			MinVersion:         tls.VersionTLS12,
			GetConfigForClient: r.GetConfigForClient,
			ClientAuth:         tls.RequireAndVerifyClientCert,
			ClientCAs:          pool,
		}, &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return tlsCert, nil
			},
			RootCAs: pool,
		}},
		{"fail GetClientCertificate", &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return tlsCert, nil
			},
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  pool,
		}, &tls.Config{
			MinVersion:           tls.VersionTLS12,
			GetClientCertificate: r.GetClientCertificate,
			RootCAs:              pool,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				// 	t.Error("missing peer certificate")
				// }
				fmt.Fprintf(w, "ok")
			}))
			srv.TLS = tt.serverConfig
			srv.StartTLS()
			// We need to set Certificates to nil, because if the hello message does not
			// have a SNI, this certificate will be used.
			srv.TLS.Certificates = nil
			defer srv.Close()

			// Create url with localhost
			dnsURL := getLocalHostURL(t, srv.URL)

			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.TLSClientConfig = tt.clientConfig
			tr.TLSClientConfig = &tls.Config{
				MinVersion:           tls.VersionTLS12,
				GetClientCertificate: r.GetClientCertificate,
				RootCAs:              pool,
			}

			trNoCert := http.DefaultTransport.(*http.Transport).Clone()
			trNoCert.TLSClientConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			}
			c := &http.Client{Transport: tr}
			if _, err := c.Get(dnsURL); err == nil {
				t.Errorf("http.Client.Get() error = %v, wantErr true", err)
			}
		})
	}
}
