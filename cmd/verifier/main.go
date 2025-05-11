package main

// The only synchronization happening between the write path and the read path
// is via the filesystem. The only signal the write path sends to clients is
// successful completion of an add-chain request. Thus, we only need to have the
// workload print to standard output after the completion of an add-chain
// request. We should examine the filesystem for self-consistency and check that
// submitted entries from successful add-chain requests are present. We should
// also confirm that the local storage, checkpoints, and cache are sufficiently
// consistent that the write path can start up again.

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"filippo.io/keygen"
	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/ctlog"
	"filippo.io/torchwood"
	"github.com/google/certificate-transparency-go/x509util"
	"golang.org/x/crypto/hkdf"
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
	reconstructedDirectory := os.Args[1]
	stdoutFilename := os.Args[2]

	// Change to the recovered directory. This represents a possible state of
	// the working directory after a crash.
	err := os.Chdir(reconstructedDirectory)
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

	// Read stdout from the workload.
	file, err := os.Open(stdoutFilename)
	if err != nil {
		fatalError(logger, "failed to read stdout file", "err", err)
	}
	defer file.Close()

	// Count how many certificates were successfully submitted.
	var entryCount int64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "Submitted certificate" {
			entryCount++
		} else {
			fatalError(logger, "Unexpected stdout line: %v", line)
		}
	}

	// Fetch the latest checkpoint from the lock backend. If there is no
	// checkpoint, that's okay because execution may have stopped before the
	// initial sequencer run.
	logId := sha256.Sum256(cfgPubKey)
	lockedCheckpoint, err := db.Fetch(ctx, logId)
	if err == nil {
		checkpoint, err := parseCheckpoint(lockedCheckpoint.Bytes())
		if err != nil {
			fatalError(logger, "failed to parse checkpoint", "err", err)
		}
		// The number of entries in the checkpoint should either match the number of
		// successful add-chain requests, or it should be one greater if there was a
		// crash between writing a checkpoint out to the database and returning
		// success.
		if checkpoint.N != entryCount && checkpoint.N != entryCount+1 {
			fatalError(logger, "wrong number of entries", "expected", entryCount, "recovered", checkpoint.N)
		}
	} else if err.Error() != "checkpoint not found" {
		fatalError(logger, "failed to fetch checkpoint", "err", err)
	}

	// Load the log, in order to make use of built-in consistency checks.
	l, err := ctlog.LoadLog(ctx, cc)
	if err != nil {
		fatalError(logger, "failed to load log", "err", err)
	}
	l.CloseCache()
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}

func parseCheckpoint(checkpoint []byte) (sunlight.Checkpoint, error) {
	// Strip the signatures, then parse the checkpoint.
	s := string(checkpoint)
	newlinePosition1 := strings.IndexByte(s, '\n')
	newlinePosition2 := strings.IndexByte(s[newlinePosition1+1:], '\n') + newlinePosition1 + 1
	newlinePosition3 := strings.IndexByte(s[newlinePosition2+1:], '\n') + newlinePosition2 + 1
	return torchwood.ParseCheckpoint(s[:newlinePosition3+1])
}
