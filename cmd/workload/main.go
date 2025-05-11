package main

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"filippo.io/keygen"
	"filippo.io/sunlight/internal/ctlog"
	"github.com/google/certificate-transparency-go/x509util"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Checkpoints string
	Log         LogConfig
}

type LogConfig struct {
	Name             string
	ShortName        string
	Inception        string
	HTTPHost         string
	HTTPPrefix       string
	SubmissionPrefix string
	MonitoringPrefix string
	Roots            string
	Seed             string
	PublicKey        string
	Cache            string
	PoolSize         int
	LocalDirectory   string
	NotAfterStart    string
	NotAfterLimit    string
}

func main() {
	// Change to the workload directory. All filesystem operations within this
	// directory will be monitored.
	err := os.Chdir("workload_dir")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to change directory %v\n", err)
		os.Exit(1)
	}

	// Program initialization.
	logLevel := new(slog.LevelVar)
	logHandler := slog.Handler(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	logger := slog.New(logHandler)

	yml, err := os.ReadFile("config.yaml")
	if err != nil {
		fatalError(logger, "failed to read config file", "err", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(yml, c); err != nil {
		fatalError(logger, "failed to parse config file", "err", err)
	}

	ctx := context.Background()

	// Set up backends.
	db, err := ctlog.NewSQLiteBackend(ctx, c.Checkpoints, logger)
	if err != nil {
		fatalError(logger, "failed to create SQLite checkpoint backend", "err", err)
	}

	lc := c.Log

	b, err := ctlog.NewLocalBackend(ctx, lc.LocalDirectory, logger)
	if err != nil {
		fatalError(logger, "failed to create backend", "err", err)
	}

	// Initialize crypto assets from configuration.
	r := x509util.NewPEMCertPool()
	if err := r.AppendCertsFromPEMFile(lc.Roots); err != nil {
		fatalError(logger, "failed to load roots", "err", err)
	}

	seed, err := os.ReadFile(lc.Seed)
	if err != nil {
		fatalError(logger, "failed to load seed", "err", err)
	}

	ecdsaSecret := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("sunlight"), []byte("ECDSA P-256 log key")), ecdsaSecret); err != nil {
		fatalError(logger, "failed to derive ECDSA secret", "err", err)
	}
	k, err := keygen.ECDSA(elliptic.P256(), ecdsaSecret)
	if err != nil {
		fatalError(logger, "failed to generate ECDSA key", "err", err)
	}

	ed25519Secret := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("sunlight"), []byte("Ed25519 log key")), ed25519Secret); err != nil {
		fatalError(logger, "failed to derive Ed25519 key", "err", err)
	}
	wk := ed25519.NewKeyFromSeed(ed25519Secret)

	cfgPubKey, err := base64.StdEncoding.DecodeString(lc.PublicKey)
	if err != nil {
		fatalError(logger, "failed to parse public key base64", "err", err)
	}
	parsedPubKey, err := x509.ParsePKIXPublicKey(cfgPubKey)
	if err != nil {
		fatalError(logger, "failed to parse public key", "err", err)
	}
	if !k.PublicKey.Equal(parsedPubKey) {
		spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			fatalError(logger, "failed to marshal public key from private key for display", "err", err)
		}
		publicFromPrivate := base64.StdEncoding.EncodeToString(spki)
		fatalError(logger, "configured private and public keys do not match", "configured", lc.PublicKey, "publicFromPrivate", publicFromPrivate)
	}

	// Finalize configuration.
	notAfterStart, err := time.Parse(time.RFC3339, lc.NotAfterStart)
	if err != nil {
		fatalError(logger, "failed to parse NotAfterStart", "err", err)
	}
	notAfterLimit, err := time.Parse(time.RFC3339, lc.NotAfterLimit)
	if err != nil {
		fatalError(logger, "failed to parse NotAfterLimit", "err", err)
	}

	cc := &ctlog.Config{
		Name:          lc.Name,
		Key:           k,
		WitnessKey:    wk,
		Cache:         lc.Cache,
		PoolSize:      lc.PoolSize,
		Backend:       b,
		Lock:          db,
		Log:           logger,
		Roots:         r,
		NotAfterStart: notAfterStart,
		NotAfterLimit: notAfterLimit,
	}

	// Load the log. We assume the log has already been created. This skips some
	// less-interesting durability issues around storing the initial snapshot,
	// etc.
	l, err := ctlog.LoadLog(ctx, cc)
	if err != nil {
		fatalError(logger, "failed to load log", "err", err)
	}
	defer l.CloseCache()

	// Get the log's HTTP handler.
	handler := l.Handler()

	// Run the sequencer as fast as is allowed by the mutex.
	sequencerGroup, sequencerContext := errgroup.WithContext(ctx)
	var done atomic.Bool
	sequencerGroup.Go(func() error {
		for !done.Load() {
			if err := l.RunSequencerOnce(sequencerContext); err != nil {
				return err
			}
		}
		return nil
	})

	// Send three add-chain requests. These will interleave with sequencer runs,
	// since each request will block until sequencing is completed.
	err = addChain(handler, "domain1.example.pem")
	if err != nil {
		fatalError(logger, "add-chain failed", "err", err)
	}
	err = addChain(handler, "domain2.example.pem")
	if err != nil {
		fatalError(logger, "add-chain failed", "err", err)
	}
	err = addChain(handler, "domain3.example.pem")
	if err != nil {
		fatalError(logger, "add-chain failed", "err", err)
	}

	// Stop running the sequencer.
	done.Store(true)
	if err := sequencerGroup.Wait(); err != nil {
		fatalError(logger, "sequencer error", "err", err)
	}
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}

func addChain(handler http.Handler, path string) error {
	certPem, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}
	certDer, _ := pem.Decode(certPem)
	if certDer == nil {
		return fmt.Errorf("failed to decode certificate")
	}
	certBase64 := base64.StdEncoding.EncodeToString(certDer.Bytes)
	requestBody := fmt.Sprintf("{\"chain\":[\"%s\"]}", certBase64)

	if handler == nil {
		return fmt.Errorf("handler must not be nil")
	}
	request := httptest.NewRequest("POST", "/ct/v1/add-chain", strings.NewReader(requestBody))
	responseRecorder := httptest.NewRecorder()
	handler.ServeHTTP(responseRecorder, request)
	responseBody, err := io.ReadAll(responseRecorder.Body)
	if err != nil {
		return fmt.Errorf("failed to read from recorder: %w", err)
	}
	if responseRecorder.Code != 200 {
		return fmt.Errorf("add-chain request did not succeed, code: %v, body: %v", responseRecorder.Code, string(responseBody))
	}
	fmt.Println("Submitted certificate")
	return nil
}
