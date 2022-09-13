package sshagentkms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Some helpers with inspiration from crypto/ssh/agent/client_test.go

// startOpenSSHAgent executes ssh-agent, and returns an Agent interface to it.
func startOpenSSHAgent(t *testing.T) (client agent.Agent, socket string, cleanup func()) {
	/* Always test with OpenSSHAgent
	if testing.Short() {
		// ssh-agent is not always available, and the key
		// types supported vary by platform.
		t.Skip("skipping test due to -short")
	}
	*/

	bin, err := exec.LookPath("ssh-agent")
	if err != nil {
		t.Skip("could not find ssh-agent")
	}

	cmd := exec.Command(bin, "-s")
	cmd.Env = []string{} // Do not let the user's environment influence ssh-agent behavior.
	cmd.Stderr = new(bytes.Buffer)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", strings.Join(cmd.Args, " "), err, cmd.Stderr)
	}

	// Output looks like:
	//
	//	SSH_AUTH_SOCK=/tmp/ssh-P65gpcqArqvH/agent.15541; export SSH_AUTH_SOCK;
	//	SSH_AGENT_PID=15542; export SSH_AGENT_PID;
	//	echo Agent pid 15542;

	fields := bytes.Split(out, []byte(";"))
	line := bytes.SplitN(fields[0], []byte("="), 2)
	line[0] = bytes.TrimLeft(line[0], "\n")
	if string(line[0]) != "SSH_AUTH_SOCK" {
		t.Fatalf("could not find key SSH_AUTH_SOCK in %q", fields[0])
	}
	socket = string(line[1])

	line = bytes.SplitN(fields[2], []byte("="), 2)
	line[0] = bytes.TrimLeft(line[0], "\n")
	if string(line[0]) != "SSH_AGENT_PID" {
		t.Fatalf("could not find key SSH_AGENT_PID in %q", fields[2])
	}
	pidStr := line[1]
	pid, err := strconv.Atoi(string(pidStr))
	if err != nil {
		t.Fatalf("Atoi(%q): %v", pidStr, err)
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}

	ac := agent.NewClient(conn)
	return ac, socket, func() {
		proc, _ := os.FindProcess(pid)
		if proc != nil {
			proc.Kill()
		}
		conn.Close()
		os.RemoveAll(filepath.Dir(socket))
	}
}

func startAgent(t *testing.T, sshagent agent.Agent) (client agent.Agent, cleanup func()) {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	go agent.ServeAgent(sshagent, c2)

	return agent.NewClient(c1), func() {
		c1.Close()
		c2.Close()
	}
}

// startKeyringAgent uses Keyring to simulate a ssh-agent Server and returns a client.
func startKeyringAgent(t *testing.T) (client agent.Agent, cleanup func()) {
	return startAgent(t, agent.NewKeyring())
}

type startTestAgentFunc func(t *testing.T, keysToAdd ...agent.AddedKey) (sshagent agent.Agent)

func startTestOpenSSHAgent(t *testing.T, keysToAdd ...agent.AddedKey) (sshagent agent.Agent) {
	sshagent, _, cleanup := startOpenSSHAgent(t)
	for _, keyToAdd := range keysToAdd {
		err := sshagent.Add(keyToAdd)
		if err != nil {
			t.Fatalf("sshagent.add: %v", err)
		}
	}
	t.Cleanup(cleanup)

	//testAgentInterface(t, sshagent, key, cert, lifetimeSecs)
	return sshagent
}

func startTestKeyringAgent(t *testing.T, keysToAdd ...agent.AddedKey) (sshagent agent.Agent) {
	sshagent, cleanup := startKeyringAgent(t)
	for _, keyToAdd := range keysToAdd {
		err := sshagent.Add(keyToAdd)
		if err != nil {
			t.Fatalf("sshagent.add: %v", err)
		}
	}
	t.Cleanup(cleanup)

	//testAgentInterface(t, agent, key, cert, lifetimeSecs)
	return sshagent
}

// netPipe is analogous to net.Pipe, but it uses a real net.Conn, and
// therefore is buffered (net.Pipe deadlocks if both sides start with
// a write.)
func netPipe() (net.Conn, net.Conn, error) {
	listener, err := netListener()
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	c1, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	c2, err := listener.Accept()
	if err != nil {
		c1.Close()
		return nil, nil, err
	}

	return c1, c2, nil
}

// netListener creates a localhost network listener.
func netListener() (net.Listener, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		listener, err = net.Listen("tcp", "[::1]:0")
		if err != nil {
			return nil, err
		}
	}
	return listener, nil
}

func TestNew(t *testing.T) {
	comment := "Key from OpenSSHAgent"
	// Ensure we don't "inherit" any SSH_AUTH_SOCK
	os.Unsetenv("SSH_AUTH_SOCK")

	sshagent, socket, cleanup := startOpenSSHAgent(t)

	t.Setenv("SSH_AUTH_SOCK", socket)
	t.Cleanup(func() {
		os.Unsetenv("SSH_AUTH_SOCK")
		cleanup()
	})

	// Test that we can't find any signers in the agent before we have loaded them
	t.Run("No keys with OpenSSHAgent", func(t *testing.T) {
		kms, err := New(context.Background(), apiv1.Options{})
		if kms == nil || err != nil {
			t.Errorf("New() = %v, %v", kms, err)
		}
		signer, err := kms.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: "sshagentkms:" + comment})
		if err == nil || signer != nil {
			t.Errorf("SSHAgentKMS.CreateSigner() error = \"%v\", signer = \"%v\"", err, signer)
		}
	})

	// Load ssh test fixtures
	b, err := os.ReadFile("testdata/ssh")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}

	// And add that key to the agent
	err = sshagent.Add(agent.AddedKey{PrivateKey: privateKey, Comment: comment})
	if err != nil {
		t.Fatalf("sshagent.add: %v", err)
	}

	// And test that we can find it when it's loaded
	t.Run("Keys with OpenSSHAgent", func(t *testing.T) {
		kms, err := New(context.Background(), apiv1.Options{})
		if kms == nil || err != nil {
			t.Errorf("New() = %v, %v", kms, err)
		}
		signer, err := kms.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: "sshagentkms:" + comment})
		if err != nil || signer == nil {
			t.Errorf("SSHAgentKMS.CreateSigner() error = \"%v\", signer = \"%v\"", err, signer)
		}
	})
}

func TestNewFromAgent(t *testing.T) {
	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name            string
		args            args
		sshagentstarter startTestAgentFunc
		wantErr         bool
	}{
		{"ok OpenSSHAgent", args{context.Background(), apiv1.Options{}}, startTestOpenSSHAgent, false},
		{"ok KeyringAgent", args{context.Background(), apiv1.Options{}}, startTestKeyringAgent, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewFromAgent(tt.args.ctx, tt.args.opts, tt.sshagentstarter(t))
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFromAgent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				t.Errorf("NewFromAgent() = %v", got)
			}
		})
	}
}

func TestSSHAgentKMS_Close(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"ok", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &SSHAgentKMS{}
			if err := k.Close(); (err != nil) != tt.wantErr {
				t.Errorf("SSHAgentKMS.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSSHAgentKMS_CreateSigner(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := pemutil.Serialize(pk)
	if err != nil {
		t.Fatal(err)
	}
	pemBlockPassword, err := pemutil.Serialize(pk, pemutil.WithPassword([]byte("pass")))
	if err != nil {
		t.Fatal(err)
	}

	// Read and decode file using standard packages
	b, err := os.ReadFile("testdata/priv.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	block.Bytes, err = x509.DecryptPEMBlock(block, []byte("pass")) //nolint
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Create a public PEM
	b, err = x509.MarshalPKIXPublicKey(pk.Public())
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})

	// Load ssh test fixtures
	sshPubKeyStr, err := os.ReadFile("testdata/ssh.pub")
	if err != nil {
		t.Fatal(err)
	}
	_, comment, _, _, err := ssh.ParseAuthorizedKey(sshPubKeyStr)
	if err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile("testdata/ssh")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	sshPrivateKey, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	wrappedSSHPrivateKey := NewWrappedSignerFromSSHSigner(sshPrivateKey)

	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.Signer
		wantErr bool
	}{
		{"signer", args{&apiv1.CreateSignerRequest{Signer: pk}}, pk, false},
		{"pem", args{&apiv1.CreateSignerRequest{SigningKeyPEM: pem.EncodeToMemory(pemBlock)}}, pk, false},
		{"pem password", args{&apiv1.CreateSignerRequest{SigningKeyPEM: pem.EncodeToMemory(pemBlockPassword), Password: []byte("pass")}}, pk, false},
		{"file", args{&apiv1.CreateSignerRequest{SigningKey: "testdata/priv.pem", Password: []byte("pass")}}, pk2, false},
		{"sshagent", args{&apiv1.CreateSignerRequest{SigningKey: "sshagentkms:" + comment}}, wrappedSSHPrivateKey, false},
		{"sshagent Nonexistant", args{&apiv1.CreateSignerRequest{SigningKey: "sshagentkms:Nonexistant"}}, nil, true},
		{"fail", args{&apiv1.CreateSignerRequest{}}, nil, true},
		{"fail bad pem", args{&apiv1.CreateSignerRequest{SigningKeyPEM: []byte("bad pem")}}, nil, true},
		{"fail bad password", args{&apiv1.CreateSignerRequest{SigningKey: "testdata/priv.pem", Password: []byte("bad-pass")}}, nil, true},
		{"fail not a signer", args{&apiv1.CreateSignerRequest{SigningKeyPEM: pub}}, nil, true},
		{"fail not a signer from file", args{&apiv1.CreateSignerRequest{SigningKey: "testdata/pub.pem"}}, nil, true},
		{"fail missing", args{&apiv1.CreateSignerRequest{SigningKey: "testdata/missing"}}, nil, true},
	}
	starters := []struct {
		name    string
		starter startTestAgentFunc
	}{
		{"startTestOpenSSHAgent", startTestOpenSSHAgent},
		{"startTestKeyringAgent", startTestKeyringAgent},
	}
	for _, starter := range starters {
		k, err := NewFromAgent(context.Background(), apiv1.Options{}, starter.starter(t, agent.AddedKey{PrivateKey: privateKey, Comment: comment}))
		if err != nil {
			t.Fatal(err)
		}
		for _, tt := range tests {
			t.Run(starter.name+"/"+tt.name, func(t *testing.T) {
				got, err := k.CreateSigner(tt.args.req)
				if (err != nil) != tt.wantErr {
					t.Errorf("SSHAgentKMS.CreateSigner() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				// nolint:gocritic
				switch s := got.(type) {
				case *WrappedSSHSigner:
					gotPkS := s.Signer.PublicKey().(*agent.Key).String() + "\n"
					wantPkS := string(sshPubKeyStr)
					if !reflect.DeepEqual(gotPkS, wantPkS) {
						t.Errorf("SSHAgentKMS.CreateSigner() = %T, want %T", gotPkS, wantPkS)
						t.Errorf("SSHAgentKMS.CreateSigner() = %v, want %v", gotPkS, wantPkS)
					}
				default:
					if !reflect.DeepEqual(got, tt.want) {
						t.Errorf("SSHAgentKMS.CreateSigner() = %T, want %T", got, tt.want)
						t.Errorf("SSHAgentKMS.CreateSigner() = %v, want %v", got, tt.want)
					}
				}
			})
		}
	}
}

func TestSSHAgentKMS_GetPublicKey(t *testing.T) {
	b, err := os.ReadFile("testdata/pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// Load ssh test fixtures
	b, err = os.ReadFile("testdata/ssh.pub")
	if err != nil {
		t.Fatal(err)
	}
	sshPubKey, comment, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile("testdata/ssh")
	if err != nil {
		t.Fatal(err)
	}
	// crypto.PrivateKey
	sshPrivateKey, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"key", args{&apiv1.GetPublicKeyRequest{Name: "testdata/pub.pem"}}, pub, false},
		{"cert", args{&apiv1.GetPublicKeyRequest{Name: "testdata/cert.crt"}}, pub, false},
		{"sshagent", args{&apiv1.GetPublicKeyRequest{Name: "sshagentkms:" + comment}}, sshPubKey, false},
		{"sshagent Nonexistant", args{&apiv1.GetPublicKeyRequest{Name: "sshagentkms:Nonexistant"}}, nil, true},
		{"fail not exists", args{&apiv1.GetPublicKeyRequest{Name: "testdata/missing"}}, nil, true},
		{"fail type", args{&apiv1.GetPublicKeyRequest{Name: "testdata/cert.key"}}, nil, true},
	}
	starters := []struct {
		name    string
		starter startTestAgentFunc
	}{
		{"startTestOpenSSHAgent", startTestOpenSSHAgent},
		{"startTestKeyringAgent", startTestKeyringAgent},
	}
	for _, starter := range starters {
		k, err := NewFromAgent(context.Background(), apiv1.Options{}, starter.starter(t, agent.AddedKey{PrivateKey: sshPrivateKey, Comment: comment}))
		if err != nil {
			t.Fatal(err)
		}
		for _, tt := range tests {
			t.Run(starter.name+"/"+tt.name, func(t *testing.T) {
				got, err := k.GetPublicKey(tt.args.req)
				if (err != nil) != tt.wantErr {
					t.Errorf("SSHAgentKMS.GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				// nolint:gocritic
				switch tt.want.(type) {
				case ssh.PublicKey:
					// If we want a ssh.PublicKey, protote got to a
					got, err = ssh.NewPublicKey(got)
					if err != nil {
						t.Fatal(err)
					}
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("SSHAgentKMS.GetPublicKey() = %T, want %T", got, tt.want)
					t.Errorf("SSHAgentKMS.GetPublicKey() = %v, want %v", got, tt.want)
				}
			})
		}
	}
}

func TestSSHAgentKMS_CreateKey(t *testing.T) {
	starters := []struct {
		name    string
		starter startTestAgentFunc
	}{
		{"startTestOpenSSHAgent", startTestOpenSSHAgent},
		{"startTestKeyringAgent", startTestKeyringAgent},
	}
	for _, starter := range starters {
		k, err := NewFromAgent(context.Background(), apiv1.Options{}, starter.starter(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Run(starter.name+"/CreateKey", func(t *testing.T) {
			got, err := k.CreateKey(&apiv1.CreateKeyRequest{
				Name:               "sshagentkms:0",
				SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			})
			if got != nil {
				t.Error("SSHAgentKMS.CreateKey() shoudn't return a value")
			}
			if err == nil {
				t.Error("SSHAgentKMS.CreateKey() didn't return a value")
			}
		})
	}
}

func TestWrappedSSHSigner(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	message, err := randutil.Salt(128)
	if err != nil {
		t.Fatal(err)
	}

	ws := NewWrappedSignerFromSSHSigner(sshSigner)
	if !reflect.DeepEqual(ws.Public(), sshSigner.PublicKey()) {
		t.Errorf("WrappedSigner.Public() = %v, want %v", ws.Public(), sshSigner.PublicKey())
	}

	sig, err := ws.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Errorf("WrappedSigner.Public() error = %v", err)
	}
	if !ed25519.Verify(pub, message, sig) {
		t.Error("ed25519.Verify() = false, want true")
	}
	sshSig := ws.(*WrappedSSHSigner).LastSignature()
	if err := sshSigner.PublicKey().Verify(message, sshSig); err != nil {
		t.Errorf("ssh.PublicKey.Verify() error = %v", err)
	}
}

func TestWrappedSSHSigner_agent(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshSigner, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	message, err := randutil.Salt(128)
	if err != nil {
		t.Fatal(err)
	}

	sshAgent, err := NewFromAgent(context.Background(), apiv1.Options{}, startTestKeyringAgent(t, agent.AddedKey{PrivateKey: priv, Comment: "go-test-key"}))
	if err != nil {
		t.Errorf("NewFromAgent() error = %v", err)
	}
	signer, err := sshAgent.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: "sshagentkms:go-test-key",
	})
	if err != nil {
		t.Errorf("SSHAgentKMS.CreateSigner() error = %v", err)
	}
	sig, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Errorf("WrappedSigner.Public() error = %v", err)
	}
	if !ed25519.Verify(pub, message, sig) {
		t.Error("ed25519.Verify() = false, want true")
	}
	sshSig := signer.(*WrappedSSHSigner).LastSignature()
	if err := sshSigner.PublicKey().Verify(message, sshSig); err != nil {
		t.Errorf("ssh.PublicKey.Verify() error = %v", err)
	}
}
