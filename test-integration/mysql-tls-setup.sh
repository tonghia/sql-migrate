#!/bin/bash

# Tweak PATH for Travis
export PATH=$PATH:$HOME/gopath/bin

set -e

export MYSQL_TLS_WORKDIR=${MYSQL_TLS_WORKDIR:-/tmp/sql-migrate-mtls-test}
export CERT_DIR=${CERT_DIR:-$MYSQL_TLS_WORKDIR/certs}
export MYSQL_CONTAINER=${MYSQL_CONTAINER:-sql-migrate-mtls-mysql}
export MYSQL_IMAGE=${MYSQL_IMAGE:-mysql:8.0}
export MYSQL_PORT=${MYSQL_PORT:-13306}
export MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD:-rootpass}

export MYSQL_CA_USER=${MYSQL_CA_USER:-caonly}
export MYSQL_CA_PASSWORD=${MYSQL_CA_PASSWORD:-caonlypass}
export MYSQL_CA_DATABASE=${MYSQL_CA_DATABASE:-test_caonly}

export MYSQL_X509_USER=${MYSQL_X509_USER:-migrate}
export MYSQL_X509_PASSWORD=${MYSQL_X509_PASSWORD:-migratepass}
export MYSQL_X509_DATABASE=${MYSQL_X509_DATABASE:-test_mtls}

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Missing required command: $1" >&2
		exit 1
	fi
}

log() {
	printf '\n==> %s\n' "$*" >&2
}

generate_certs() {
	if [ -f "$CERT_DIR/ca.pem" ] &&
		[ -f "$CERT_DIR/server-cert.pem" ] &&
		[ -f "$CERT_DIR/server-key.pem" ] &&
		[ -f "$CERT_DIR/client-cert.pem" ] &&
		[ -f "$CERT_DIR/client-key.pem" ]; then
		log "Using existing certificates in $CERT_DIR"
		return
	fi

	log "Generating test certificates in $CERT_DIR"
	mkdir -p "$CERT_DIR"
	rm -f "$CERT_DIR"/*.pem "$CERT_DIR"/*.cnf "$CERT_DIR"/*.srl

	(
		cd "$CERT_DIR"

		openssl genrsa 2048 >ca-key.pem
		openssl req -new -x509 -nodes -days 3650 \
			-key ca-key.pem \
			-subj "/CN=sql-migrate-test-ca" \
			-out ca.pem

		cat >server-ext.cnf <<EOF
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF

		openssl req -newkey rsa:2048 -nodes \
			-keyout server-key.pem \
			-subj "/CN=localhost" \
			-out server-req.pem
		openssl x509 -req -in server-req.pem -days 3650 \
			-CA ca.pem \
			-CAkey ca-key.pem \
			-set_serial 01 \
			-extfile server-ext.cnf \
			-out server-cert.pem

		cat >client-ext.cnf <<EOF
extendedKeyUsage=clientAuth
EOF

		openssl req -newkey rsa:2048 -nodes \
			-keyout client-key.pem \
			-subj "/CN=sql-migrate-client" \
			-out client-req.pem
		openssl x509 -req -in client-req.pem -days 3650 \
			-CA ca.pem \
			-CAkey ca-key.pem \
			-set_serial 02 \
			-extfile client-ext.cnf \
			-out client-cert.pem

		chmod 644 ./*.pem
	)
}

root_auth_succeeds() {
	docker exec "$MYSQL_CONTAINER" mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -Nse "SELECT 1" >/dev/null 2>&1
}

start_mysql() {
	log "Starting MySQL container $MYSQL_CONTAINER on port $MYSQL_PORT"
	docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true

	docker run --name "$MYSQL_CONTAINER" --rm -d \
		-e MYSQL_ROOT_PASSWORD="$MYSQL_ROOT_PASSWORD" \
		-p "$MYSQL_PORT:3306" \
		-v "$CERT_DIR:/etc/mysql/certs:ro" \
		"$MYSQL_IMAGE" \
		--ssl-ca=/etc/mysql/certs/ca.pem \
		--ssl-cert=/etc/mysql/certs/server-cert.pem \
		--ssl-key=/etc/mysql/certs/server-key.pem \
		--require_secure_transport=ON >/dev/null
}

wait_mysql() {
	log "Waiting for MySQL to become ready"

	for _ in {1..60}; do
		if root_auth_succeeds; then
			return
		fi

		sleep 2
	done

	docker logs "$MYSQL_CONTAINER" >&2 || true
	echo "MySQL did not become ready in time." >&2
	exit 1
}

configure_users() {
	log "Resetting TLS test users and databases"

	docker exec "$MYSQL_CONTAINER" mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "
DROP DATABASE IF EXISTS ${MYSQL_CA_DATABASE};
CREATE DATABASE ${MYSQL_CA_DATABASE};
DROP USER IF EXISTS '${MYSQL_CA_USER}'@'%';
CREATE USER '${MYSQL_CA_USER}'@'%' IDENTIFIED BY '${MYSQL_CA_PASSWORD}' REQUIRE SSL;
GRANT ALL PRIVILEGES ON ${MYSQL_CA_DATABASE}.* TO '${MYSQL_CA_USER}'@'%';

DROP DATABASE IF EXISTS ${MYSQL_X509_DATABASE};
CREATE DATABASE ${MYSQL_X509_DATABASE};
DROP USER IF EXISTS '${MYSQL_X509_USER}'@'%';
CREATE USER '${MYSQL_X509_USER}'@'%' IDENTIFIED BY '${MYSQL_X509_PASSWORD}' REQUIRE X509;
GRANT ALL PRIVILEGES ON ${MYSQL_X509_DATABASE}.* TO '${MYSQL_X509_USER}'@'%';

FLUSH PRIVILEGES;
"
}

show_setup() {
	log "Checking MySQL TLS setup"

	docker exec "$MYSQL_CONTAINER" mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e "
SHOW VARIABLES LIKE 'have_ssl';
SHOW VARIABLES LIKE 'require_secure_transport';
SELECT user, host, ssl_type FROM mysql.user WHERE user IN ('${MYSQL_CA_USER}', '${MYSQL_X509_USER}');
"

	cat <<EOF

CA-only test:
  SQL_MIGRATE=/path/to/sql-migrate ./test-integration/mysql-tls.sh

Client-certificate test:
  MYSQL_USER=${MYSQL_X509_USER} \\
  MYSQL_PASSWORD=${MYSQL_X509_PASSWORD} \\
  DATABASE_NAME=${MYSQL_X509_DATABASE} \\
  MYSQL_CLIENT_CERT=${CERT_DIR}/client-cert.pem \\
  MYSQL_CLIENT_KEY=${CERT_DIR}/client-key.pem \\
  SQL_MIGRATE=/path/to/sql-migrate \\
  ./test-integration/mysql-tls.sh
EOF
}

require_cmd docker
require_cmd openssl

mkdir -p "$MYSQL_TLS_WORKDIR" "$CERT_DIR"
generate_certs
start_mysql
wait_mysql
configure_users
show_setup
