package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/go-sql-driver/mysql"
	//revive:disable-next-line:dot-imports
	. "gopkg.in/check.v1"
	"gopkg.in/yaml.v2"
)

type ConfigSuite struct{}

var _ = Suite(&ConfigSuite{})

func (*ConfigSuite) TestEnvironmentParsesMySQLTLSFields(c *C) {
	config := map[string]*Environment{}
	err := yaml.Unmarshal([]byte(`
development:
  dialect: mysql
  datasource: user:password@tcp(localhost:3306)/dbname?parseTime=true
  dir: migrations
  mysql-client-cert: /certs/client-cert.pem
  mysql-client-key: /certs/client-key.pem
  mysql-ca-cert: /certs/ca.pem
  mysql-server-name: mysql.example.com
  mysql-tls-config: sql-migrate-test
`), &config)
	c.Assert(err, IsNil)

	env := config["development"]
	c.Assert(env.MySQLClientCert, Equals, "/certs/client-cert.pem")
	c.Assert(env.MySQLClientKey, Equals, "/certs/client-key.pem")
	c.Assert(env.MySQLCACert, Equals, "/certs/ca.pem")
	c.Assert(env.MySQLServerName, Equals, "mysql.example.com")
	c.Assert(env.MySQLTLSConfig, Equals, "sql-migrate-test")
}

func (*ConfigSuite) TestPrepareMySQLTLSRegistersConfigAndPreservesDatasource(c *C) {
	dir := c.MkDir()
	certFile, keyFile, caFile := writeTestCertificates(c, dir)
	configName := "sql-migrate-test-valid"
	defer mysql.DeregisterTLSConfig(configName)

	env := &Environment{
		Dialect:         "mysql",
		DataSource:      "user:password@tcp(localhost:3306)/dbname?parseTime=true&timeout=5s",
		MySQLClientCert: certFile,
		MySQLClientKey:  keyFile,
		MySQLCACert:     caFile,
		MySQLServerName: "localhost",
		MySQLTLSConfig:  configName,
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, IsNil)

	cfg, err := mysql.ParseDSN(env.DataSource)
	c.Assert(err, IsNil)
	c.Assert(cfg.TLSConfig, Equals, configName)
	c.Assert(cfg.ParseTime, Equals, true)
	c.Assert(cfg.Timeout, Equals, 5*time.Second)
}

func (*ConfigSuite) TestPrepareMySQLTLSAllowsCAOnlyConfig(c *C) {
	dir := c.MkDir()
	_, _, caFile := writeTestCertificates(c, dir)
	configName := "sql-migrate-test-ca-only"
	defer mysql.DeregisterTLSConfig(configName)

	env := &Environment{
		Dialect:         "mysql",
		DataSource:      "user:password@tcp(localhost:3306)/dbname?parseTime=true&timeout=5s",
		MySQLCACert:     caFile,
		MySQLServerName: "localhost",
		MySQLTLSConfig:  configName,
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, IsNil)

	cfg, err := mysql.ParseDSN(env.DataSource)
	c.Assert(err, IsNil)
	c.Assert(cfg.TLSConfig, Equals, configName)
	c.Assert(cfg.ParseTime, Equals, true)
	c.Assert(cfg.Timeout, Equals, 5*time.Second)
}

func (*ConfigSuite) TestPrepareMySQLTLSDefaultsConfigName(c *C) {
	dir := c.MkDir()
	certFile, keyFile, _ := writeTestCertificates(c, dir)
	defer mysql.DeregisterTLSConfig("sql-migrate")

	env := &Environment{
		Dialect:         "mysql",
		DataSource:      "user:password@tcp(localhost:3306)/dbname?parseTime=true",
		MySQLClientCert: certFile,
		MySQLClientKey:  keyFile,
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, IsNil)

	cfg, err := mysql.ParseDSN(env.DataSource)
	c.Assert(err, IsNil)
	c.Assert(cfg.TLSConfig, Equals, "sql-migrate")
	c.Assert(cfg.ParseTime, Equals, true)
}

func (*ConfigSuite) TestPrepareMySQLTLSDefaultsConfigNameForCAOnly(c *C) {
	dir := c.MkDir()
	_, _, caFile := writeTestCertificates(c, dir)
	defer mysql.DeregisterTLSConfig("sql-migrate")

	env := &Environment{
		Dialect:     "mysql",
		DataSource:  "user:password@tcp(localhost:3306)/dbname?parseTime=true",
		MySQLCACert: caFile,
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, IsNil)

	cfg, err := mysql.ParseDSN(env.DataSource)
	c.Assert(err, IsNil)
	c.Assert(cfg.TLSConfig, Equals, "sql-migrate")
	c.Assert(cfg.ParseTime, Equals, true)
}

func (*ConfigSuite) TestPrepareMySQLTLSNoFieldsLeavesDatasource(c *C) {
	env := &Environment{
		Dialect:    "mysql",
		DataSource: "user:password@tcp(localhost:3306)/dbname?parseTime=true",
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, IsNil)
	c.Assert(env.DataSource, Equals, "user:password@tcp(localhost:3306)/dbname?parseTime=true")
}

func (*ConfigSuite) TestPrepareMySQLTLSNonMySQLIgnoresFields(c *C) {
	env := &Environment{
		Dialect:         "postgres",
		DataSource:      "dbname=test sslmode=disable",
		MySQLClientCert: "/missing/client-cert.pem",
		MySQLClientKey:  "/missing/client-key.pem",
		MySQLCACert:     "/missing/ca.pem",
		MySQLServerName: "localhost",
		MySQLTLSConfig:  "sql-migrate-test-postgres",
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, IsNil)
	c.Assert(env.DataSource, Equals, "dbname=test sslmode=disable")
}

func (*ConfigSuite) TestPrepareMySQLTLSRequiresClientKey(c *C) {
	env := &Environment{
		Dialect:         "mysql",
		DataSource:      "user:password@tcp(localhost:3306)/dbname?parseTime=true",
		MySQLClientCert: "/certs/client-cert.pem",
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, ErrorMatches, ".*mysql-client-key.*required.*")
}

func (*ConfigSuite) TestPrepareMySQLTLSRequiresClientCert(c *C) {
	env := &Environment{
		Dialect:        "mysql",
		DataSource:     "user:password@tcp(localhost:3306)/dbname?parseTime=true",
		MySQLClientKey: "/certs/client-key.pem",
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, ErrorMatches, ".*mysql-client-cert.*required.*")
}

func (*ConfigSuite) TestPrepareMySQLTLSReportsMissingCertFile(c *C) {
	dir := c.MkDir()
	_, keyFile, _ := writeTestCertificates(c, dir)
	missingCert := filepath.Join(dir, "missing-client-cert.pem")

	env := &Environment{
		Dialect:         "mysql",
		DataSource:      "user:password@tcp(localhost:3306)/dbname?parseTime=true",
		MySQLClientCert: missingCert,
		MySQLClientKey:  keyFile,
		MySQLTLSConfig:  "sql-migrate-test-missing-cert",
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, ErrorMatches, ".*"+missingCert+".*")
}

func (*ConfigSuite) TestPrepareMySQLTLSReportsMissingCAFile(c *C) {
	missingCA := filepath.Join(c.MkDir(), "missing-ca.pem")

	env := &Environment{
		Dialect:        "mysql",
		DataSource:     "user:password@tcp(localhost:3306)/dbname?parseTime=true",
		MySQLCACert:    missingCA,
		MySQLTLSConfig: "sql-migrate-test-missing-ca",
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, ErrorMatches, ".*"+missingCA+".*")
}

func (*ConfigSuite) TestPrepareMySQLTLSReportsInvalidCertPair(c *C) {
	dir := c.MkDir()
	certFile := filepath.Join(dir, "client-cert.pem")
	keyFile := filepath.Join(dir, "client-key.pem")
	c.Assert(os.WriteFile(certFile, []byte("not a cert"), 0644), IsNil)
	c.Assert(os.WriteFile(keyFile, []byte("not a key"), 0644), IsNil)

	env := &Environment{
		Dialect:         "mysql",
		DataSource:      "user:password@tcp(localhost:3306)/dbname?parseTime=true",
		MySQLClientCert: certFile,
		MySQLClientKey:  keyFile,
		MySQLTLSConfig:  "sql-migrate-test-invalid-pair",
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, ErrorMatches, ".*client certificate.*")
}

func (*ConfigSuite) TestPrepareMySQLTLSRejectsDatasourceTLSConflict(c *C) {
	dir := c.MkDir()
	certFile, keyFile, _ := writeTestCertificates(c, dir)

	env := &Environment{
		Dialect:         "mysql",
		DataSource:      "user:password@tcp(localhost:3306)/dbname?parseTime=true&tls=skip-verify",
		MySQLClientCert: certFile,
		MySQLClientKey:  keyFile,
		MySQLTLSConfig:  "sql-migrate-test-conflict",
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, ErrorMatches, ".*datasource.*tls.*conflict.*")
}

func (*ConfigSuite) TestPrepareMySQLTLSRejectsConfigNameWithoutTLSMaterial(c *C) {
	env := &Environment{
		Dialect:        "mysql",
		DataSource:     "user:password@tcp(localhost:3306)/dbname?parseTime=true",
		MySQLTLSConfig: "sql-migrate-test-no-material",
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, ErrorMatches, ".*mysql-ca-cert.*mysql-client-cert.*required.*")
}

func (*ConfigSuite) TestPrepareMySQLTLSRejectsServerNameWithoutTLSMaterial(c *C) {
	env := &Environment{
		Dialect:         "mysql",
		DataSource:      "user:password@tcp(localhost:3306)/dbname?parseTime=true",
		MySQLServerName: "localhost",
	}

	err := prepareMySQLTLS(env)
	c.Assert(err, ErrorMatches, ".*mysql-ca-cert.*mysql-client-cert.*required.*")
}

func writeTestCertificates(c *C, dir string) (string, string, string) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sql-migrate-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	c.Assert(err, IsNil)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "sql-migrate-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	c.Assert(err, IsNil)

	certFile := filepath.Join(dir, "client-cert.pem")
	keyFile := filepath.Join(dir, "client-key.pem")
	caFile := filepath.Join(dir, "ca.pem")

	writePEM(c, certFile, "CERTIFICATE", clientDER)
	writePEM(c, caFile, "CERTIFICATE", caDER)
	writePrivateKey(c, keyFile, clientKey)

	return certFile, keyFile, caFile
}

func writePEM(c *C, filename, typ string, der []byte) {
	file, err := os.Create(filename)
	c.Assert(err, IsNil)
	defer func() { _ = file.Close() }()

	err = pem.Encode(file, &pem.Block{Type: typ, Bytes: der})
	c.Assert(err, IsNil)
}

func writePrivateKey(c *C, filename string, key *rsa.PrivateKey) {
	der := x509.MarshalPKCS1PrivateKey(key)
	writePEM(c, filename, "RSA PRIVATE KEY", der)
}
