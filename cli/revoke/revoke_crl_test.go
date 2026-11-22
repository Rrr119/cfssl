package revoke

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/cli"
)

// writeTestCA creates a self-signed CA and writes its certificate and key
// to the given directory, returning the file paths and the parsed CA cert.
func writeTestCA(t *testing.T, dir string) (caFile, caKeyFile string, caCert *x509.Certificate) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Revoke Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	caFile = filepath.Join(dir, "ca.pem")
	caKeyFile = filepath.Join(dir, "ca-key.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caKeyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return caFile, caKeyFile, caCert
}

// TestRevokeRefreshesCRL verifies the revocation linkage: revoking a
// certificate with -crl-out regenerates a CRL from the certificate store
// that lists exactly the revoked, unexpired certificates and is signed by
// the CA.
func TestRevokeRefreshesCRL(t *testing.T) {
	dir := t.TempDir()
	caFile, caKeyFile, caCert := writeTestCA(t, dir)
	crlFile := filepath.Join(dir, "ca.crl")
	dbFile := filepath.Join(dir, "certstore.db")
	dbConfigFile := filepath.Join(dir, "db-config.json")

	// Start from the migrated development certificate store.
	seedDB, err := os.ReadFile("../../certdb/testdb/certstore_development.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbFile, seedDB, 0600); err != nil {
		t.Fatal(err)
	}

	dbConfig, err := json.Marshal(map[string]string{
		"driver":      "sqlite3",
		"data_source": dbFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbConfigFile, dbConfig, 0600); err != nil {
		t.Fatal(err)
	}

	// Seed the certificate store with two unexpired certificates.
	db := testdb.SQLiteDB(dbFile)
	dbAccessor := sql.NewAccessor(db)
	expiry := time.Now().Add(time.Hour).UTC()
	for _, serial := range []string{"1001", "1002"} {
		err := dbAccessor.InsertCertificate(certdb.CertificateRecord{
			Serial: serial,
			AKI:    "deadbeef",
			Expiry: expiry,
			PEM:    "placeholder",
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Revoke 1001 and refresh the CRL in the same step.
	err = revokeMain([]string{}, cli.Config{
		Serial:        "1001",
		AKI:           "deadbeef",
		DBConfigFile:  dbConfigFile,
		CAFile:        caFile,
		CAKeyFile:     caKeyFile,
		CRLOutFile:    crlFile,
		CRLExpiration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	crlPEM, err := os.ReadFile(crlFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(crlPEM)
	if block == nil {
		t.Fatal("CRL output is not PEM encoded")
	}
	revList, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	// The CRL must be signed by the CA.
	if err := revList.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("CRL signature does not verify against CA: %v", err)
	}

	// The CRL must contain exactly the revoked certificate.
	if len(revList.RevokedCertificateEntries) != 1 {
		t.Fatalf("expected 1 revoked certificate in CRL, got %d", len(revList.RevokedCertificateEntries))
	}
	if got := revList.RevokedCertificateEntries[0].SerialNumber.String(); got != "1001" {
		t.Fatalf("CRL contains serial %s, expected 1001", got)
	}

	// Revoking the second certificate refreshes the CRL again.
	err = revokeMain([]string{}, cli.Config{
		Serial:        "1002",
		AKI:           "deadbeef",
		DBConfigFile:  dbConfigFile,
		CAFile:        caFile,
		CAKeyFile:     caKeyFile,
		CRLOutFile:    crlFile,
		CRLExpiration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	crlPEM, err = os.ReadFile(crlFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(crlPEM)
	revList, err = x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(revList.RevokedCertificateEntries) != 2 {
		t.Fatalf("expected 2 revoked certificates in refreshed CRL, got %d", len(revList.RevokedCertificateEntries))
	}

	// Refreshing without CA material must fail.
	if _, err := RefreshCRLFromDB(dbAccessor, "", "", crlFile, time.Hour); err == nil {
		t.Fatal("expected error when CA certificate and key are missing")
	}
}
