package batchsign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	localsigner "github.com/cloudflare/cfssl/signer/local"
)

// shortLivedCAConfig defines a signing policy with a "short" profile
// issuing certificates valid for 10 minutes, as used for short-lived
// internal PKI certificates.
const shortLivedCAConfig = `{
	"signing": {
		"default": {
			"expiry": "10m",
			"usages": ["digital signature"]
		},
		"profiles": {
			"short": {
				"expiry": "10m",
				"usages": ["signing", "digital signature", "key encipherment", "server auth", "client auth"]
			}
		}
	}
}`

const shortProfileExpiry = 10 * time.Minute

// newTestCA creates a self-signed ECDSA CA for testing.
func newTestCA(t *testing.T) (cert *x509.Certificate, key crypto.Signer, certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Batchsign Test Internal CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return cert, priv, certPEM, keyPEM
}

// newShortProfileSigner builds a local signer with the short-lived profile.
func newShortProfileSigner(t *testing.T, cert *x509.Certificate, key crypto.Signer) *localsigner.Signer {
	t.Helper()

	cfg, err := config.LoadConfig([]byte(shortLivedCAConfig))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Signing.Profiles["short"]; !ok {
		t.Fatal("short profile missing from loaded config")
	}

	s, err := localsigner.NewSigner(key, cert, x509.ECDSAWithSHA256, cfg.Signing)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// makeCSR generates an ECDSA key and a PEM encoded CSR for the given CN.
func makeCSR(t *testing.T, cn string) []byte {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestBatchSignAndVerify1000 issues 1000 short-lived certificates with the
// "short" profile and verifies every one of them against the CA: chain of
// trust, hostname, lifetime, and serial uniqueness.
func TestBatchSignAndVerify1000(t *testing.T) {
	const batchSize = 1000

	caCert, caKey, _, _ := newTestCA(t)
	s := newShortProfileSigner(t, caCert, caKey)

	jobs := make([]Job, 0, batchSize)
	for i := 0; i < batchSize; i++ {
		cn := fmt.Sprintf("node-%04d.internal.example.com", i)
		jobs = append(jobs, Job{Name: cn, CSR: makeCSR(t, cn)})
	}

	start := time.Now()
	results := BatchSign(s, "short", "", jobs, 16)
	t.Logf("signed %d certificates in %s", batchSize, time.Since(start).Round(time.Millisecond))

	if len(results) != batchSize {
		t.Fatalf("expected %d results, got %d", batchSize, len(results))
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	serials := make(map[string]bool, batchSize)
	verified := 0

	for i, res := range results {
		if res.Err != nil {
			t.Fatalf("job %d (%s) failed to sign: %v", i, res.Name, res.Err)
		}

		cert, err := helpers.ParseCertificatePEM(res.Cert)
		if err != nil {
			t.Fatalf("job %d (%s): cannot parse issued certificate: %v", i, res.Name, err)
		}

		// Chain of trust and hostname verification.
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:     roots,
			DNSName:   res.Name,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Fatalf("certificate %s failed verification: %v", res.Name, err)
		}

		// Subject CN is carried through from the CSR.
		if cert.Subject.CommonName != res.Name {
			t.Fatalf("certificate %s has unexpected CN %q", res.Name, cert.Subject.CommonName)
		}

		// The short profile bounds the certificate lifetime: the
		// certificate must expire within the 10 minute profile
		// expiry (lifetime includes the default 5 minute backdate).
		lifetime := cert.NotAfter.Sub(cert.NotBefore)
		if lifetime > shortProfileExpiry+6*time.Minute {
			t.Fatalf("certificate %s lifetime %s exceeds short profile bound", res.Name, lifetime)
		}
		if time.Until(cert.NotAfter) > shortProfileExpiry+time.Minute {
			t.Fatalf("certificate %s expires too far in the future: %s", res.Name, cert.NotAfter)
		}

		// Serial numbers must be unique across the batch.
		serial := cert.SerialNumber.String()
		if serials[serial] {
			t.Fatalf("duplicate serial number %s issued", serial)
		}
		serials[serial] = true

		verified++
	}

	if verified != batchSize {
		t.Fatalf("verified %d certificates, expected %d", verified, batchSize)
	}
}

// TestBatchSignUnknownProfile documents CFSSL profile resolution: an
// unknown profile falls back to the default profile, while a signer with
// no usable profile at all fails every job.
func TestBatchSignUnknownProfile(t *testing.T) {
	caCert, caKey, _, _ := newTestCA(t)
	s := newShortProfileSigner(t, caCert, caKey)

	jobs := []Job{{Name: "bad", CSR: makeCSR(t, "bad.internal.example.com")}}
	results := BatchSign(s, "no-such-profile", "", jobs, 1)
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("unknown profile should fall back to the default profile: %v", results[0].Err)
	}

	// Without a default profile there is nothing to fall back to.
	s.SetPolicy(&config.Signing{Profiles: map[string]*config.SigningProfile{}})
	results = BatchSign(s, "no-such-profile", "", jobs, 1)
	if len(results) != 1 || results[0].Err == nil {
		t.Fatal("expected signing to fail when no profile can be resolved")
	}
}

// TestBatchSignMain exercises the CLI entry point: CSRs on disk are signed
// with the configured short profile and certificates land in the output
// directory.
func TestBatchSignMain(t *testing.T) {
	_, _, caPEM, caKeyPEM := newTestCA(t)

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	caKeyFile := filepath.Join(dir, "ca-key.pem")
	configFile := filepath.Join(dir, "ca-config.json")
	csrDir := filepath.Join(dir, "csrs")
	outDir := filepath.Join(dir, "certs")

	for path, contents := range map[string][]byte{
		caFile:     caPEM,
		caKeyFile:  caKeyPEM,
		configFile: []byte(shortLivedCAConfig),
	} {
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(csrDir, 0755); err != nil {
		t.Fatal(err)
	}

	const n = 8
	for i := 0; i < n; i++ {
		cn := fmt.Sprintf("cli-%02d.internal.example.com", i)
		if err := os.WriteFile(filepath.Join(csrDir, cn+".csr"), makeCSR(t, cn), 0600); err != nil {
			t.Fatal(err)
		}
	}

	cfg, err := config.LoadFile(configFile)
	if err != nil {
		t.Fatal(err)
	}

	err = batchsignMain([]string{}, cli.Config{
		CAFile:     caFile,
		CAKeyFile:  caKeyFile,
		ConfigFile: configFile,
		CFG:        cfg,
		Profile:    "short",
		CSRDir:     csrDir,
		OutDir:     outDir,
		NumWorkers: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Fatalf("expected %d certificates in %s, got %d", n, outDir, len(entries))
	}
	for _, entry := range entries {
		certPEM, err := os.ReadFile(filepath.Join(outDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := helpers.ParseCertificatePEM(certPEM); err != nil {
			t.Fatalf("output %s is not a valid certificate: %v", entry.Name(), err)
		}
	}

	// A missing CSR directory must be reported.
	if err := batchsignMain([]string{}, cli.Config{}); err == nil {
		t.Fatal("expected error when -csr-dir is not provided")
	}
}

// TestSummaryJSON ensures the summary type marshals as expected.
func TestSummaryJSON(t *testing.T) {
	out, err := json.Marshal(summary{Signed: 999, Failed: 1, OutDir: "/tmp/out", Failure: map[string]string{"x": "boom"}})
	if err != nil {
		t.Fatal(err)
	}
	var decoded summary
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Signed != 999 || decoded.Failed != 1 || decoded.Failure["x"] != "boom" {
		t.Fatalf("unexpected summary round trip: %s", out)
	}
}
