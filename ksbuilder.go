package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	flag "github.com/spf13/pflag"
	"software.sslmate.com/src/go-pkcs12"
)

type pkcs12File struct {
	cacerts           []*x509.Certificate
	intermediatecerts []*x509.Certificate
	privkey           *rsa.PrivateKey
	entitycert        *x509.Certificate
}

func (p12 *pkcs12File) addCertificate(cert *x509.Certificate) error {
	if cert != nil {
		// Check if CA
		if cert.IsCA {
			if cert.Issuer.String() == cert.Subject.String() {
				p12.cacerts = append(p12.cacerts, cert)
			} else {
				p12.intermediatecerts = append(p12.intermediatecerts, cert)
			}
			return nil
		} else {
			if p12.entitycert != nil {
				return errors.New("cannot have two end-entity certs in keystore. The only one should be for the keystore's private key")
			}
			// Use buffer to copy and dereference iteration variable pointer
			buffer := cert
			p12.entitycert = buffer
		}
	}
	return nil
}

func (p12 *pkcs12File) addKey(key *rsa.PrivateKey) error {
	if key != nil {
		if p12.privkey != nil {
			return errors.New("cannot have two private keys in keystore")
		}
	}
	return nil
}

func (p12 *pkcs12File) writeFile(path string, storepass string, perm fs.FileMode) (err error) {
	// First compile intermediate and ca certs into a single slice
	var allcerts []*x509.Certificate = append(p12.cacerts, p12.intermediatecerts...)

	var payload []byte
	if p12.privkey != nil {
		if p12.entitycert == nil {
			return errors.New("failed to generate keystore because privkey was set but found no matching end-entity certificate")
		}
		// Verify pubcert and privkey match
		payload, err = pkcs12.Encode(rand.Reader, p12.privkey, p12.entitycert, allcerts, storepass)
		if err != nil {
			return
		}
	} else {
		payload, err = pkcs12.EncodeTrustStore(rand.Reader, allcerts, storepass)
		if err != nil {
			return
		}
	}

	return os.WriteFile(path, payload, perm)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	var outfile, storepass string
	var certdirs, certfiles []string
	var recurse bool

	flag.StringSliceVarP(&certdirs, "dir", "d", []string{os.Getenv("KSBUILDER_DIR")}, "directory to add files from")
	flag.StringSliceVarP(&certfiles, "file", "f", make([]string, 0), "certificate or key file to add")
	flag.StringVarP(&outfile, "out", "o", os.Getenv("KSBUILDER_OUT"), "path to output file")
	flag.StringVarP(&storepass, "password", "p", os.Getenv("KSBUILDER_PASSWORD"), "keystore password for output file")
	flag.BoolVarP(&recurse, "recursive", "r", false, "recurse directories")

	flag.Parse()

	fmt.Printf("certdirs = %v\n", certdirs)
	fmt.Printf("outfile = %v\n", outfile)
	fmt.Printf("storepass = %v\n", storepass)
	fmt.Printf("recurse = %v\n", recurse)

	// Validate input
	if outfile == "" {
		fmt.Println("ERROR: No output file specified. Please use --out $FILE or set environment variable KSBUILDER_OUT.")
		panic("The variable 'outfile' cannot be nil.")
	}

	if storepass == "" {
		fmt.Printf("WARN: password was not set, defaulting to '%s'.\n", pkcs12.DefaultPassword)
		storepass = pkcs12.DefaultPassword
	}

	var p12 = pkcs12File{}

	for _, dir := range certdirs {
		if tmppath, err := filepath.Abs(dir); err == nil {
			dir = tmppath
		}
		fmt.Printf("INFO: Walking %s...\n", dir)
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if path != dir {
					if recurse {
						fmt.Printf("INFO: Adding %s to directory array: recurse == true.\n", path)
						certdirs = append(certdirs, path)
					} else {
						fmt.Printf("INFO: Skipping %s: is a directory and recurse == false.\n", path)
					}
				}
				return nil
			}
			if extension := filepath.Ext(path); extension != ".crt" && extension != ".key" && extension != ".pem" {
				fmt.Printf("INFO: Skipping %s: extension is not '.crt', '.key', or '.pem'.\n", path)
				return nil
			}
			certfiles = append(certfiles, path)
			return nil
		})
		check(err)
		fmt.Printf("INFO: Completed walk of %s.\n", dir)
	}

	for _, path := range certfiles {
		bytes, err := os.ReadFile(path)
		if err != nil {
			check(fmt.Errorf("failed to load %s: %v", path, err))
		}

		var block *pem.Block
		var certsBytes []byte
		for {
			block, bytes = pem.Decode(bytes)
			if block == nil { // No more PEM blocks found.
				break
			}
			switch block.Type {
			case "PRIVATE KEY":
				parseResult, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
				if privkey, ok := parseResult.(*rsa.PrivateKey); ok {
					check(p12.addKey(privkey))
				} else {
					check(fmt.Errorf("failed to parse private key from %s", path))
				}
			case "RSA PRIVATE KEY":
				if privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
					check(p12.addKey(privkey))
				}
				check(err)
			case "CERTIFICATE":
				certsBytes = append(certsBytes, block.Bytes...)
			}
		}

		certs, err := x509.ParseCertificates(certsBytes)
		if err != nil {
			check(fmt.Errorf("failed to parse certificate in %s: %v", path, err))
		}

		for _, cert := range certs {
			err := p12.addCertificate(cert)
			if err != nil {
				check(fmt.Errorf("failed to parse a certificate in %s: %v", path, err))
			}
		}
	}

	fmt.Printf("Writing output file to %s...\n", outfile)
	err := p12.writeFile(outfile, storepass, 0644)
	check(err)
	fmt.Printf("Successfully completed keystore generation and saved to %s. Ciao.", outfile)
}
