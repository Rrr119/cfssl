// Package batchsign implements the batchsign command, which signs a
// directory of CSRs in bulk using a signing profile. It is intended
// for internal PKI deployments that need to issue large batches of
// short-lived certificates.
package batchsign

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// Usage text of 'cfssl batchsign'
var batchsignUsageText = `cfssl batchsign -- sign every CSR in a directory with a given CA and signing profile

Usage of batchsign:
        cfssl batchsign -ca cert -ca-key key -csr-dir dir -out-dir dir [-config config] [-profile profile] [-hostname hostname] [-num-workers n] [-db-config db-config]
        cfssl batchsign -remote remote_host -csr-dir dir -out-dir dir [-config config] [-profile profile] [-label label]

Every file ending in ".csr" inside -csr-dir is signed; the resulting
certificate is written to -out-dir with the same base name and a ".pem"
extension. Signing is performed concurrently with -num-workers workers
(default 10). If any CSR fails to sign, the command exits non-zero after
reporting all failures.

Flags:
`

// Flags of 'cfssl batchsign'
var batchsignFlags = []string{"ca", "ca-key", "config", "profile", "label", "remote",
	"hostname", "csr-dir", "out-dir", "num-workers", "db-config",
	"mutual-tls-cert", "mutual-tls-key"}

// Job is a single certificate signing task in a batch.
type Job struct {
	// Name is the base name used for the output certificate file.
	Name string
	// CSR is the PEM encoded certificate signing request.
	CSR []byte
	// Hosts, when non-empty, overrides the hosts in the CSR.
	Hosts []string
}

// Result is the outcome of signing one Job.
type Result struct {
	Name string
	Cert []byte
	Err  error
}

// BatchSign signs every job with the given signer and profile using a
// pool of workers, and returns one Result per job, in order.
func BatchSign(s signer.Signer, profile, label string, jobs []Job, workers int) []Result {
	if workers < 1 {
		workers = 1
	}
	results := make([]Result, len(jobs))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, job := range jobs {
		wg.Add(1)
		go func(i int, job Job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cert, err := s.Sign(signer.SignRequest{
				Hosts:   job.Hosts,
				Request: string(job.CSR),
				Profile: profile,
				Label:   label,
			})
			results[i] = Result{Name: job.Name, Cert: cert, Err: err}
		}(i, job)
	}
	wg.Wait()
	return results
}

// summary is the JSON report printed at the end of a batch run.
type summary struct {
	Signed  int               `json:"signed"`
	Failed  int               `json:"failed"`
	OutDir  string            `json:"out_dir"`
	Failure map[string]string `json:"failure,omitempty"`
}

// batchsignMain is the main CLI of the batchsign command.
func batchsignMain(args []string, c cli.Config) error {
	if len(args) > 0 {
		return errors.New("argument is provided but not defined; please refer to the usage by flag -h")
	}
	if c.CSRDir == "" {
		return errors.New("CSR directory is required (provide with -csr-dir)")
	}
	if c.OutDir == "" {
		return errors.New("output directory is required (provide with -out-dir)")
	}

	s, err := sign.SignerFromConfig(c)
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(c.CSRDir)
	if err != nil {
		return err
	}

	var hosts []string
	if c.Hostname != "" {
		hosts = signer.SplitHosts(c.Hostname)
	}

	var jobs []Job
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".csr") {
			continue
		}
		csrPEM, err := os.ReadFile(filepath.Join(c.CSRDir, entry.Name()))
		if err != nil {
			return err
		}
		jobs = append(jobs, Job{
			Name:  strings.TrimSuffix(entry.Name(), ".csr"),
			CSR:   csrPEM,
			Hosts: hosts,
		})
	}
	if len(jobs) == 0 {
		return fmt.Errorf("no .csr files found in %s", c.CSRDir)
	}

	if err := os.MkdirAll(c.OutDir, 0755); err != nil {
		return err
	}

	log.Infof("batch signing %d CSRs with %d workers", len(jobs), c.NumWorkers)
	results := BatchSign(s, c.Profile, c.Label, jobs, c.NumWorkers)

	rep := summary{OutDir: c.OutDir}
	for _, res := range results {
		if res.Err != nil {
			log.Errorf("failed to sign %s: %v", res.Name, res.Err)
			rep.Failed++
			if rep.Failure == nil {
				rep.Failure = map[string]string{}
			}
			rep.Failure[res.Name] = res.Err.Error()
			continue
		}
		outFile := filepath.Join(c.OutDir, res.Name+".pem")
		if err := os.WriteFile(outFile, res.Cert, 0644); err != nil {
			return err
		}
		rep.Signed++
	}

	out, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", out)

	if rep.Failed > 0 {
		return fmt.Errorf("%d of %d CSRs failed to sign", rep.Failed, len(results))
	}
	return nil
}

// Command assembles the definition of Command 'batchsign'
var Command = &cli.Command{
	UsageText: batchsignUsageText,
	Flags:     batchsignFlags,
	Main:      batchsignMain,
}
