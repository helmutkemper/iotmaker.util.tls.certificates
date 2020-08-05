package iotmakerUtilTlsCertificates

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"github.com/helmutkemper/util"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Load a file by name or file path
func LoadFile(filePath string) (file []byte, err error) {
	var certFileExists = util.FileCheckExists(filePath)
	if certFileExists == false {
		filePath = filepath.Base(filePath)
		filePath, err = util.FileFindInThree(filePath)
	}

	file, err = ioutil.ReadFile(filePath)

	return file, err
}

// Get a x509certificate from java key store
func JavaKeyStoreGetCertificateByAlias(keyStore KeyStore, alias string) (certificate *x509.Certificate, err error) {
	return keyStore.GetCert(alias)
}

// Get a x509certificate and private key from java key store
func JavaKeyStoreGetCertificates(keyStore KeyStore, alias, password string) (privateKey crypto.PrivateKey, certificates []*x509.Certificate, err error) {
	return keyStore.GetPrivateKeyAndCerts(alias, []byte(password))
}

// Get a list of certificates from java key store
func JavaKeyStoreListCertificates(keyStore KeyStore) (list []string) {
	return keyStore.ListCerts()
}

// Parser a java key store file
func JavaKeyStoreLoadFile(filePath string, password string) (keyStore KeyStore, err error) {
	var filePointer *os.File

	var certFileExists = util.FileCheckExists(filePath)
	if certFileExists == false {
		filePath = filepath.Base(filePath)
		filePath, err = util.FileFindInThree(filePath)
		if err != nil {
			return
		}
	}

	filePointer, err = os.Open(filePath)
	if err != nil {
		return
	}

	err = keyStore.Parse(filePointer, []byte(password))
	return
}

func NewTlsFromJavaKeyStore(jksPath, alias, password string) (config *tls.Config, err error) {
	var keyStore KeyStore
	var certificate *x509.Certificate

	config = newTlsConfig()

	keyStore, err = JavaKeyStoreLoadFile(jksPath, password)
	if err != nil {
		return
	}

	certificate, err = JavaKeyStoreGetCertificateByAlias(keyStore, alias)
	if err != nil {
		return
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(certificate)
	config.RootCAs = caCertPool

	return
}

func NewTlsFromX509KeyPar(certFile, keyFile []byte) (config *tls.Config, err error) {
	var certificate tls.Certificate

	certificate, err = tls.X509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}

	config = newTlsConfig()
	config.Certificates = []tls.Certificate{
		certificate,
	}
	return
}

func NewTlsFromX509KeyPairFile(certFilePath, keyFilePath string) (config *tls.Config, err error) {
	var certFile, keyFile []byte

	config = newTlsConfig()

	certFile, err = LoadFile(certFilePath)
	if err != nil {
		return
	}

	keyFile, err = LoadFile(keyFilePath)
	if err != nil {
		return
	}

	return NewTlsFromX509KeyPar(certFile, keyFile)
}

func NewTlsFromCertificates(certificatesList [][]byte) (config *tls.Config, err error) {
	config = newTlsConfig()

	caCertPool := x509.NewCertPool()
	for _, certificate := range certificatesList {
		caCertPool.AppendCertsFromPEM(certificate)
	}

	config.RootCAs = caCertPool

	return
}

func newTlsConfig() (config *tls.Config) {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}
}
