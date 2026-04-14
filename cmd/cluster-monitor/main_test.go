package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestCheckCertificate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "monitor-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	m := &Monitor{}

	t.Run("Missing file", func(t *testing.T) {
		m.checkCertificate(filepath.Join(tmpDir, "missing.pem"))
		// Should not panic and should log a warning (can't easily check logs here without more refactor)
	})

	t.Run("Invalid PEM", func(t *testing.T) {
		path := filepath.Join(tmpDir, "invalid.pem")
		err := os.WriteFile(path, []byte("not a pem"), 0644)
		assert.NoError(t, err)
		m.checkCertificate(path)
	})

	t.Run("Valid certificate", func(t *testing.T) {
		path := filepath.Join(tmpDir, "valid.pem")
		createTestCert(t, path, time.Now().Add(24*time.Hour))
		m.checkCertificate(path)
	})

	t.Run("Expired certificate", func(t *testing.T) {
		path := filepath.Join(tmpDir, "expired.pem")
		createTestCert(t, path, time.Now().Add(-1*time.Hour))
		m.checkCertificate(path)
	})

	t.Run("Nearing expiry certificate", func(t *testing.T) {
		path := filepath.Join(tmpDir, "near.pem")
		createTestCert(t, path, time.Now().Add(12*time.Hour))
		m.checkCertificate(path)
	})

	t.Run("Multiple certificates in bundle", func(t *testing.T) {
		path := filepath.Join(tmpDir, "bundle.pem")
		createMultiCertBundle(t, path, time.Now().Add(-1*time.Hour), time.Now().Add(24*time.Hour))
		m.checkCertificate(path)
	})
}

func createMultiCertBundle(t *testing.T, path string, notAfter1, notAfter2 time.Time) {
	priv1, _ := rsa.GenerateKey(rand.Reader, 2048)
	template1 := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter1,
	}
	der1, _ := x509.CreateCertificate(rand.Reader, template1, template1, &priv1.PublicKey, priv1)

	priv2, _ := rsa.GenerateKey(rand.Reader, 2048)
	template2 := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter2,
	}
	der2, _ := x509.CreateCertificate(rand.Reader, template2, template2, &priv2.PublicKey, priv2)

	f, _ := os.Create(path)
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der1})
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der2})
}

func TestNewMonitor(t *testing.T) {
	os.Setenv("MONITOR_INTERVAL", "10s")
	os.Setenv("MONGO_URL", "mongodb://localhost:27017")
	os.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/test.sock")
	defer func() {
		os.Unsetenv("MONITOR_INTERVAL")
		os.Unsetenv("MONGO_URL")
		os.Unsetenv("SPIFFE_ENDPOINT_SOCKET")
	}()

	m := NewMonitor()
	assert.Equal(t, 10*time.Second, m.Interval)
	assert.Equal(t, "mongodb://localhost:27017", m.MongoURL)
	assert.Equal(t, "unix:///tmp/test.sock", m.SpiffeSocket)
}

func createTestCert(t *testing.T, path string, notAfter time.Time) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	assert.NoError(t, err)

	certOut, err := os.Create(path)
	assert.NoError(t, err)
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	assert.NoError(t, err)
}

type mockSpiffeSource struct {
	svid *x509svid.SVID
	err  error
}

func (m *mockSpiffeSource) GetX509SVID() (*x509svid.SVID, error) {
	return m.svid, m.err
}

func (m *mockSpiffeSource) Close() error {
	return nil
}

func TestCheckSpireAgent(t *testing.T) {
	oldNewX509Source := newX509Source
	defer func() { newX509Source = oldNewX509Source }()

	os.Setenv("SPIFFE_ENDPOINT_SOCKET", "/tmp/spire-test.sock")
	defer os.Unsetenv("SPIFFE_ENDPOINT_SOCKET")

	t.Run("SPIRE Agent Healthy", func(t *testing.T) {
		m := &Monitor{SpiffeSocket: "/tmp/spire-test.sock"}
		newX509Source = func(ctx context.Context) (SpiffeSource, error) {
			return &mockSpiffeSource{svid: &x509svid.SVID{}}, nil
		}
		m.checkSpireAgent(context.Background())
		assert.NotNil(t, m.x509Source)
	})

	t.Run("SPIRE Agent Unreachable", func(t *testing.T) {
		m := &Monitor{SpiffeSocket: "/tmp/spire-test.sock"}
		newX509Source = func(ctx context.Context) (SpiffeSource, error) {
			return nil, os.ErrNotExist
		}
		m.checkSpireAgent(context.Background())
		assert.Nil(t, m.x509Source)
	})

	t.Run("SPIRE Agent Failed to provide SVID", func(t *testing.T) {
		m := &Monitor{SpiffeSocket: "/tmp/spire-test.sock"}
		newX509Source = func(ctx context.Context) (SpiffeSource, error) {
			return &mockSpiffeSource{err: os.ErrPermission}, nil
		}
		m.checkSpireAgent(context.Background())
		assert.NotNil(t, m.x509Source)
	})
}

func TestEvaluateReplicaSetStatus(t *testing.T) {
	m := &Monitor{}

	t.Run("Valid status with bson.A and bson.D", func(t *testing.T) {
		status := bson.M{
			"members": bson.A{
				bson.D{
					{Key: "name", Value: "host1"},
					{Key: "stateStr", Value: "PRIMARY"},
					{Key: "health", Value: 1.0},
				},
				bson.D{
					{Key: "name", Value: "host2"},
					{Key: "stateStr", Value: "SECONDARY"},
					{Key: "health", Value: 1.0},
				},
				bson.D{
					{Key: "name", Value: "host3"},
					{Key: "stateStr", Value: "SECONDARY"},
					{Key: "health", Value: 0.0},
				},
			},
		}

		healthy, total := m.evaluateReplicaSetStatus(status)
		if healthy != 2 {
			t.Errorf("expected 2 healthy nodes, got %d", healthy)
		}
		if total != 3 {
			t.Errorf("expected 3 total nodes, got %d", total)
		}
	})

	t.Run("Status with bson.M and integer health", func(t *testing.T) {
		status := bson.M{
			"members": bson.A{
				bson.M{
					"name":     "host1",
					"stateStr": "PRIMARY",
					"health":   int32(1),
				},
				bson.M{
					"name":     "host2",
					"stateStr": "SECONDARY",
					"health":   int64(0),
				},
			},
		}

		healthy, total := m.evaluateReplicaSetStatus(status)
		if healthy != 1 {
			t.Errorf("expected 1 healthy node, got %d", healthy)
		}
		if total != 2 {
			t.Errorf("expected 2 total nodes, got %d", total)
		}
	})

	t.Run("Status with missing members", func(t *testing.T) {
		status := bson.M{
			"ok": 1,
		}

		healthy, total := m.evaluateReplicaSetStatus(status)
		if healthy != 0 {
			t.Errorf("expected 0 healthy nodes, got %d", healthy)
		}
		if total != 0 {
			t.Errorf("expected 0 total nodes, got %d", total)
		}
	})
}
