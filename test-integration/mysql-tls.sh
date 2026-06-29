#!/bin/bash

# Tweak PATH for Travis
export PATH=$PATH:$HOME/gopath/bin

set -e

# Defaults match the local Docker TLS setup used for manual testing.
# Set MYSQL_CLIENT_CERT and MYSQL_CLIENT_KEY to test a REQUIRE X509 user.
export SQL_MIGRATE=${SQL_MIGRATE:-sql-migrate}
export MYSQL_USER=${MYSQL_USER:-caonly}
export DATABASE_NAME=${DATABASE_NAME:-test_caonly}
export MYSQL_PASSWORD=${MYSQL_PASSWORD:-caonlypass}
export MYSQL_HOST=${MYSQL_HOST:-127.0.0.1}
export MYSQL_PORT=${MYSQL_PORT:-13306}
export MYSQL_CA_CERT=${MYSQL_CA_CERT:-/tmp/sql-migrate-mtls-test/certs/ca.pem}
export MYSQL_CLIENT_CERT=${MYSQL_CLIENT_CERT:-}
export MYSQL_CLIENT_KEY=${MYSQL_CLIENT_KEY:-}
export MYSQL_SERVER_NAME=${MYSQL_SERVER_NAME:-localhost}
export MYSQL_TLS_CONFIG=${MYSQL_TLS_CONFIG:-sql-migrate-tls}
export MYSQL_TLS_CONFIG_FILE=${MYSQL_TLS_CONFIG_FILE:-/tmp/sql-migrate-mysql-tls-dbconfig.yml}

if [ ! -f "$MYSQL_CA_CERT" ]; then
	echo "MYSQL_CA_CERT does not exist: $MYSQL_CA_CERT" >&2
	exit 1
fi

if [ -n "$MYSQL_CLIENT_CERT" ] && [ -z "$MYSQL_CLIENT_KEY" ]; then
	echo "MYSQL_CLIENT_KEY is required when MYSQL_CLIENT_CERT is set" >&2
	exit 1
fi

if [ -n "$MYSQL_CLIENT_KEY" ] && [ -z "$MYSQL_CLIENT_CERT" ]; then
	echo "MYSQL_CLIENT_CERT is required when MYSQL_CLIENT_KEY is set" >&2
	exit 1
fi

cat >"$MYSQL_TLS_CONFIG_FILE" <<EOF
mysql_tls:
  dialect: mysql
  datasource: ${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(${MYSQL_HOST}:${MYSQL_PORT})/${DATABASE_NAME}?parseTime=true
  dir: test-migrations
  mysql-ca-cert: ${MYSQL_CA_CERT}
  mysql-server-name: ${MYSQL_SERVER_NAME}
  mysql-tls-config: ${MYSQL_TLS_CONFIG}
EOF

if [ -n "$MYSQL_CLIENT_CERT" ]; then
	cat >>"$MYSQL_TLS_CONFIG_FILE" <<EOF
  mysql-client-cert: ${MYSQL_CLIENT_CERT}
  mysql-client-key: ${MYSQL_CLIENT_KEY}
EOF
fi

OPTIONS="-config=$MYSQL_TLS_CONFIG_FILE -env mysql_tls"

set -x

$SQL_MIGRATE status $OPTIONS
$SQL_MIGRATE up $OPTIONS
$SQL_MIGRATE down $OPTIONS
$SQL_MIGRATE redo $OPTIONS
$SQL_MIGRATE status $OPTIONS
