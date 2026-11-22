// Package revoke implements the revoke command.
package revoke

import (
	"crypto"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/dbconf"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/crl"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
)

var revokeUsageTxt = `cfssl revoke -- revoke a certificate in the certificate store

Usage:

Revoke a certificate:
	   cfssl revoke -db-config config_file -serial serial -aki authority_key_id [-reason reason]

Revoke a certificate and refresh the CRL from the certificate store:
	   cfssl revoke -db-config config_file -serial serial -aki authority_key_id -ca ca_cert -ca-key ca_key -crl-out crl_file [-expiry duration]

Reason can be an integer code or a string in ReasonFlags in RFC 5280

Flags:
`

var revokeFlags = []string{"serial", "reason", "ca", "ca-key", "crl-out", "expiry"}

func revokeMain(args []string, c cli.Config) error {
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}

	if len(c.Serial) == 0 {
		return errors.New("serial number is required but not provided")
	}

	if len(c.AKI) == 0 {
		return errors.New("authority key id is required but not provided")
	}

	if c.DBConfigFile == "" {
		return errors.New("need DB config file (provide with -db-config)")
	}

	db, err := dbconf.DBFromConfig(c.DBConfigFile)
	if err != nil {
		return err
	}

	dbAccessor := sql.NewAccessor(db)

	reasonCode, err := ocsp.ReasonStringToCode(c.Reason)
	if err != nil {
		log.Error("Invalid reason code: ", err)
		return err
	}

	if err := dbAccessor.RevokeCertificate(c.Serial, c.AKI, reasonCode); err != nil {
		return err
	}

	if c.CRLOutFile == "" {
		return nil
	}

	_, err = RefreshCRLFromDB(dbAccessor, c.CAFile, c.CAKeyFile, c.CRLOutFile, c.CRLExpiration)
	return err
}

// RefreshCRLFromDB regenerates a CRL covering every revoked, unexpired
// certificate in the certificate store, signs it with the given CA, and
// writes it PEM-encoded to outFile. It returns the number of revoked
// certificates included in the CRL.
func RefreshCRLFromDB(dbAccessor certdb.Accessor, caFile, caKeyFile, outFile string, expiry time.Duration) (int, error) {
	if caFile == "" || caKeyFile == "" {
		return 0, errors.New("need CA certificate and key (provide with -ca and -ca-key) to refresh CRL")
	}

	caCertPEM, err := helpers.ReadBytes(caFile)
	if err != nil {
		return 0, err
	}
	caCert, err := helpers.ParseCertificatePEM(caCertPEM)
	if err != nil {
		return 0, err
	}

	caKeyPEM, err := helpers.ReadBytes(caKeyFile)
	if err != nil {
		return 0, err
	}
	password := os.Getenv("CFSSL_CA_PK_PASSWORD")
	var caKey crypto.Signer
	if password == "" {
		caKey, err = helpers.ParsePrivateKeyPEM(caKeyPEM)
	} else {
		caKey, err = helpers.ParsePrivateKeyPEMWithPassword(caKeyPEM, []byte(password))
	}
	if err != nil {
		return 0, err
	}

	records, err := dbAccessor.GetRevokedAndUnexpiredCertificates()
	if err != nil {
		return 0, err
	}

	crlBytes, err := crl.NewCRLFromDB(records, caCert, caKey, expiry)
	if err != nil {
		return 0, err
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
	if err := os.WriteFile(outFile, crlPEM, 0644); err != nil {
		return 0, err
	}

	log.Infof("refreshed CRL at %s with %d revoked certificates", outFile, len(records))
	return len(records), nil
}

// Command assembles the definition of Command 'revoke'
var Command = &cli.Command{
	UsageText: revokeUsageTxt,
	Flags:     revokeFlags,
	Main:      revokeMain,
}
