package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/i2-open/i2goSignals/pkg/logger"
	"github.com/i2-open/i2goSignals/pkg/tlsSupport"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type SpiffeSource interface {
	GetX509SVID() (*x509svid.SVID, error)
	Close() error
}

var (
	log           = logger.Sub("CLUSTER-MONITOR")
	newX509Source = func(ctx context.Context) (SpiffeSource, error) {
		return tlsSupport.NewX509Source(ctx)
	}
)

type Monitor struct {
	Interval     time.Duration
	MongoURL     string
	CertPaths    []string
	SpiffeSocket string
	x509Source   SpiffeSource
}

func NewMonitor() *Monitor {
	interval := 5 * time.Minute
	if d, err := time.ParseDuration(os.Getenv("MONITOR_INTERVAL")); err == nil {
		interval = d
	}

	mongoUrl := os.Getenv("MONGO_URL")
	if mongoUrl == "" {
		mongoUrl = "mongodb://root:dockTest@mongo1:30001,mongo2:30002,mongo3:30003/?replicaSet=dbrs&tls=true&tlsAllowInvalidHostnames=true&tlsCAFile=/certs/ca.pem&tlsCertificateKeyFile=/certs/mongo.pem&authSource=admin"
	}

	return &Monitor{
		Interval:     interval,
		MongoURL:     mongoUrl,
		CertPaths:    []string{"/certs/mongo.pem", "/certs/ca.pem"},
		SpiffeSocket: os.Getenv(tlsSupport.EnvSpiffeSocket),
	}
}

func main() {
	log.Info("Starting Cluster Monitor")
	fmt.Println()
	fmt.Println("For development testing only.")
	fmt.Println()
	fmt.Println("Cluster monitor checks the current status of Mongo in a SPIFFE enabled cluster.  Certificate")
	fmt.Println("rotation for mongo and ca is monitored along with SPIRE Agent health and Mongo health checks.")
	fmt.Println()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := NewMonitor()

	// Initialize SPIRE source if enabled
	if tlsSupport.SpiffeEnabled() {
		source, err := newX509Source(ctx)
		if err != nil {
			log.Error("CRITICAL: Failed to initialize SPIRE source", "error", err)
		} else {
			m.x509Source = source
			defer m.x509Source.Close()
		}
	}

	// Initial check
	m.RunChecks(ctx)

	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.RunChecks(ctx)
		case <-ctx.Done():
			log.Info("Shutting down Cluster Monitor")
			return
		}
	}
}

func (m *Monitor) RunChecks(ctx context.Context) {
	log.Info("Running health checks...")

	// 1. Check SPIRE Agent
	m.checkSpireAgent(ctx)

	// 2. Check MongoDB Cluster
	m.checkMongoCluster(ctx)

	// 3. Check Certificates
	for _, p := range m.CertPaths {
		m.checkCertificate(p)
	}
}

func (m *Monitor) checkSpireAgent(ctx context.Context) {
	if !tlsSupport.SpiffeEnabled() {
		log.Warn("SPIFFE not enabled (SPIFFE_ENDPOINT_SOCKET missing), skipping agent check")
		return
	}

	if m.x509Source == nil {
		// Try to re-initialize if it was null
		source, err := newX509Source(ctx)
		if err != nil {
			log.Error("CRITICAL: SPIRE Agent is UNHEALTHY or unreachable", "socket", m.SpiffeSocket, "error", err)
			return
		}
		m.x509Source = source
	}

	svid, err := m.x509Source.GetX509SVID()
	if err != nil {
		log.Error("SPIRE Agent reachable but failed to provide SVID", "error", err)
	} else {
		log.Info("SPIRE Agent is HEALTHY", "spiffeID", svid.ID)
	}
}

func (m *Monitor) checkMongoCluster(ctx context.Context) {
	mongoUrl := m.MongoURL
	opts := options.Client().ApplyURI(mongoUrl)

	// Use resilient mTLS config if SPIRE is available
	if m.x509Source != nil {
		if ws, ok := m.x509Source.(*workloadapi.X509Source); ok {
			tlsCfg, err := tlsSupport.NewResilientMTLSClientConfig(ws)
			if err == nil {
				opts.SetTLSConfig(tlsCfg)
				log.Debug("Using resilient SPIFFE mTLS for MongoDB health check")
			} else {
				log.Warn("Failed to create resilient TLS config for MongoDB check", "error", err)
			}
		}
	}

	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	client, err := mongo.Connect(opts)
	if err != nil {
		log.Error("MongoDB Cluster connection FAILED", "error", err)
		return
	}
	defer func() {
		_ = client.Disconnect(context.Background())
	}()

	err = client.Ping(checkCtx, nil)
	if err != nil {
		log.Error("MongoDB Cluster Ping FAILED", "error", err)
		return
	}

	var status bson.M
	err = client.Database("admin").RunCommand(checkCtx, bson.D{{"replSetGetStatus", 1}}).Decode(&status)
	if err != nil {
		log.Warn("Could not get MongoDB replica set status", "error", err)
		return
	}

	healthyNodes, totalNodes := m.evaluateReplicaSetStatus(status)
	log.Info("MongoDB Cluster status", "healthyNodes", healthyNodes, "totalNodes", totalNodes)
}

func (m *Monitor) evaluateReplicaSetStatus(status bson.M) (healthyNodes int, totalNodes int) {

	// Unmarshal back to struct for easy and robust parsing.
	// This handles bson.M, bson.D, and various numeric types correctly.
	data, err := bson.Marshal(status)
	if err != nil {
		log.Error("Failed to re-marshal status", "error", err)
		return 0, 0
	}

	var res struct {
		Members []struct {
			Name     string  `bson:"name"`
			StateStr string  `bson:"stateStr"`
			Health   float64 `bson:"health"`
		} `bson:"members"`
	}
	if err := bson.Unmarshal(data, &res); err != nil {
		log.Warn("Unexpected format for replSetGetStatus members", "error", err)
		return 0, 0
	}

	healthyNodes = 0
	for _, m := range res.Members {
		if m.Health == 1 {
			healthyNodes++
			log.Debug("MongoDB Node is healthy", "node", m.Name, "state", m.StateStr)
		} else {
			log.Error("CRITICAL: MongoDB Node is UNHEALTHY", "node", m.Name, "state", m.StateStr)
		}
	}

	return healthyNodes, len(res.Members)
}

func (m *Monitor) checkCertificate(path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Warn("Certificate file does not exist", "path", path)
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Error("Could not read certificate file", "path", path, "error", err)
		return
	}

	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, cert)
			}
		}
		data = rest
	}

	if len(certs) == 0 {
		log.Error("No valid X.509 certificates found in PEM file", "path", path)
		return
	}

	now := time.Now()
	var bestNotAfter time.Time
	var latestNotAfter time.Time

	for _, cert := range certs {
		if cert.NotAfter.After(latestNotAfter) {
			latestNotAfter = cert.NotAfter
		}
		// "Best" is the one with the furthest expiry that is NOT already expired.
		// If all are expired, best is the one that expired last.
		if cert.NotAfter.After(now) {
			if bestNotAfter.IsZero() || cert.NotAfter.After(bestNotAfter) {
				bestNotAfter = cert.NotAfter
			}
		}
	}

	// Use latestNotAfter as best if all are expired.
	if bestNotAfter.IsZero() {
		bestNotAfter = latestNotAfter
	}

	timeLeft := bestNotAfter.Sub(now)

	if now.After(bestNotAfter) {
		log.Error("CRITICAL: Certificate has EXPIRED", "path", path, "expiredAt", bestNotAfter)
	} else if timeLeft < 24*time.Hour {
		log.Warn("URGENT: Certificate is nearing expiry", "path", path, "timeLeft", timeLeft.Round(time.Minute))
	} else {
		log.Info("Certificate is valid", "path", path, "timeLeft", timeLeft.Round(time.Hour))
	}
}
