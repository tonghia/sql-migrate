package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"runtime/debug"
	"strings"

	"github.com/go-gorp/gorp/v3"
	"github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v2"

	migrate "github.com/rubenv/sql-migrate"

	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

var dialects = map[string]gorp.Dialect{
	"sqlite3":  gorp.SqliteDialect{},
	"postgres": gorp.PostgresDialect{},
	"mysql":    gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"},
}

var (
	ConfigFile        string
	ConfigEnvironment string
)

func ConfigFlags(f *flag.FlagSet) {
	f.StringVar(&ConfigFile, "config", "dbconfig.yml", "Configuration file to use.")
	f.StringVar(&ConfigEnvironment, "env", "development", "Environment to use.")
}

type Environment struct {
	Dialect       string `yaml:"dialect"`
	DataSource    string `yaml:"datasource"`
	Dir           string `yaml:"dir"`
	TableName     string `yaml:"table"`
	SchemaName    string `yaml:"schema"`
	IgnoreUnknown bool   `yaml:"ignoreunknown"`

	MySQLClientCert string `yaml:"mysql-client-cert"`
	MySQLClientKey  string `yaml:"mysql-client-key"`
	MySQLCACert     string `yaml:"mysql-ca-cert"`
	MySQLServerName string `yaml:"mysql-server-name"`
	MySQLTLSConfig  string `yaml:"mysql-tls-config"`
}

func ReadConfig() (map[string]*Environment, error) {
	file, err := os.ReadFile(ConfigFile)
	if err != nil {
		return nil, err
	}

	config := make(map[string]*Environment)
	err = yaml.Unmarshal(file, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func GetEnvironment() (*Environment, error) {
	config, err := ReadConfig()
	if err != nil {
		return nil, err
	}

	env := config[ConfigEnvironment]
	if env == nil {
		return nil, errors.New("No environment: " + ConfigEnvironment)
	}

	if env.Dialect == "" {
		return nil, errors.New("No dialect specified")
	}

	if env.DataSource == "" {
		return nil, errors.New("No data source specified")
	}
	env.DataSource = os.ExpandEnv(env.DataSource)

	if env.Dir == "" {
		env.Dir = "migrations"
	}

	if env.TableName != "" {
		migrate.SetTable(env.TableName)
	}

	if env.SchemaName != "" {
		migrate.SetSchema(env.SchemaName)
	}

	migrate.SetIgnoreUnknown(env.IgnoreUnknown)

	return env, nil
}

func GetConnection(env *Environment) (*sql.DB, string, error) {
	if err := prepareMySQLTLS(env); err != nil {
		return nil, "", fmt.Errorf("Cannot configure MySQL TLS: %w", err)
	}

	db, err := sql.Open(env.Dialect, env.DataSource)
	if err != nil {
		return nil, "", fmt.Errorf("Cannot connect to database: %w", err)
	}

	// Make sure we only accept dialects that were compiled in.
	_, exists := dialects[env.Dialect]
	if !exists {
		return nil, "", fmt.Errorf("Unsupported dialect: %s", env.Dialect)
	}

	return db, env.Dialect, nil
}

func prepareMySQLTLS(env *Environment) error {
	if env.Dialect != "mysql" || !env.hasMySQLTLSConfig() {
		return nil
	}

	if env.MySQLClientCert == "" {
		return errors.New("mysql-client-cert is required when configuring MySQL TLS")
	}
	if env.MySQLClientKey == "" {
		return errors.New("mysql-client-key is required when configuring MySQL TLS")
	}
	if dataSourceHasTLSParam(env.DataSource) {
		return errors.New("datasource tls parameter conflicts with MySQL client certificate config")
	}

	cfg, err := mysql.ParseDSN(env.DataSource)
	if err != nil {
		return fmt.Errorf("parse MySQL datasource: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(env.MySQLClientCert, env.MySQLClientKey)
	if err != nil {
		return fmt.Errorf("load MySQL client certificate %q and key %q: %w", env.MySQLClientCert, env.MySQLClientKey, err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   env.MySQLServerName,
	}

	if env.MySQLCACert != "" {
		rootCAs := x509.NewCertPool()
		caCert, err := os.ReadFile(env.MySQLCACert)
		if err != nil {
			return fmt.Errorf("read MySQL CA certificate %q: %w", env.MySQLCACert, err)
		}
		if ok := rootCAs.AppendCertsFromPEM(caCert); !ok {
			return fmt.Errorf("read MySQL CA certificate %q: no certificates found", env.MySQLCACert)
		}
		tlsConfig.RootCAs = rootCAs
	}

	configName := env.MySQLTLSConfig
	if configName == "" {
		configName = "sql-migrate"
	}
	if err := mysql.RegisterTLSConfig(configName, tlsConfig); err != nil {
		return fmt.Errorf("register MySQL TLS config %q: %w", configName, err)
	}

	cfg.TLSConfig = configName
	env.DataSource = cfg.FormatDSN()
	return nil
}

func (env *Environment) hasMySQLTLSConfig() bool {
	return env.MySQLClientCert != "" ||
		env.MySQLClientKey != "" ||
		env.MySQLCACert != "" ||
		env.MySQLServerName != "" ||
		env.MySQLTLSConfig != ""
}

func dataSourceHasTLSParam(dataSource string) bool {
	questionMark := strings.Index(dataSource, "?")
	if questionMark == -1 {
		return false
	}

	values, err := url.ParseQuery(dataSource[questionMark+1:])
	if err != nil {
		return strings.Contains(dataSource[questionMark+1:], "tls=")
	}
	_, ok := values["tls"]
	return ok
}

// GetVersion returns the version.
func GetVersion() string {
	if buildInfo, ok := debug.ReadBuildInfo(); ok && buildInfo.Main.Version != "(devel)" {
		return buildInfo.Main.Version
	}
	return "dev"
}
