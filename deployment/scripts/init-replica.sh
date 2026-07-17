#!/usr/bin/env bash
#
# Bootstrap the MariaDB read replica from a running primary.
#
# Steps performed:
#   1. Verify primary is reachable.
#   2. Create the replication user on primary (idempotent).
#   3. Dump primary with --master-data=2 --single-transaction so we capture
#      a consistent snapshot together with its binlog coordinates.
#   4. Stop and wipe the replica volume so we start from a clean slate.
#   5. Start the replica, load the dump, configure the master pointer, and
#      START SLAVE.
#
# Run from the deployment/ directory:
#     ./scripts/init-replica.sh
#
# Requires: docker compose, .env with MYSQL_* secrets.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/.."

# shellcheck disable=SC1091
source .env

REPL_USER="${REPL_USER:-replicator}"
REPL_PASSWORD="${REPL_PASSWORD:?REPL_PASSWORD must be set in .env}"
DUMP_FILE="/tmp/suspicious-primary-snapshot.sql"

echo "==> 1/6 Checking primary reachability"
docker compose exec -T db_suspicious mariadb-admin \
    --user=root --password="${MYSQL_ROOT_PASSWORD}" status >/dev/null

echo "==> 2/6 Creating replication user on primary (idempotent)"
docker compose exec -T db_suspicious mariadb \
    --user=root --password="${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS '${REPL_USER}'@'%' IDENTIFIED BY '${REPL_PASSWORD}';
GRANT REPLICATION SLAVE ON *.* TO '${REPL_USER}'@'%';
FLUSH PRIVILEGES;
SQL

echo "==> 3/6 Dumping primary snapshot with binlog coordinates"
docker compose exec -T db_suspicious mariadb-dump \
    --user=root --password="${MYSQL_ROOT_PASSWORD}" \
    --all-databases --routines --triggers --events \
    --single-transaction --master-data=2 \
    > "${DUMP_FILE}"

# Extract MASTER_LOG_FILE / MASTER_LOG_POS from the dump's CHANGE MASTER comment
MASTER_LINE=$(grep -m1 "CHANGE MASTER TO" "${DUMP_FILE}" || true)
if [ -z "${MASTER_LINE}" ]; then
    echo "ERROR: dump did not contain CHANGE MASTER coordinates — abort." >&2
    exit 1
fi
MASTER_LOG_FILE=$(echo "${MASTER_LINE}" | sed -E "s/.*MASTER_LOG_FILE='([^']+)'.*/\1/")
MASTER_LOG_POS=$(echo "${MASTER_LINE}" | sed -E "s/.*MASTER_LOG_POS=([0-9]+).*/\1/")
echo "    master_log_file=${MASTER_LOG_FILE} master_log_pos=${MASTER_LOG_POS}"

echo "==> 4/6 Wiping replica volume"
docker compose --profile replica down db_suspicious_replica 2>/dev/null || true
docker volume rm "$(basename "$(pwd)")_db_suspicious_replica_data" 2>/dev/null || true

echo "==> 5/6 Starting replica and loading snapshot"
docker compose --profile replica up -d db_suspicious_replica
# Wait for replica to accept connections
for _ in $(seq 1 60); do
    if docker compose exec -T db_suspicious_replica mariadb-admin \
        --user=root --password="${MYSQL_ROOT_PASSWORD}" ping >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

docker compose exec -T db_suspicious_replica mariadb \
    --user=root --password="${MYSQL_ROOT_PASSWORD}" < "${DUMP_FILE}"

echo "==> 6/6 Configuring replica master pointer and starting replication"
docker compose exec -T db_suspicious_replica mariadb \
    --user=root --password="${MYSQL_ROOT_PASSWORD}" <<SQL
STOP SLAVE;
RESET SLAVE ALL;
CHANGE MASTER TO
    MASTER_HOST='db_suspicious',
    MASTER_USER='${REPL_USER}',
    MASTER_PASSWORD='${REPL_PASSWORD}',
    MASTER_LOG_FILE='${MASTER_LOG_FILE}',
    MASTER_LOG_POS=${MASTER_LOG_POS};
START SLAVE;
SQL

rm -f "${DUMP_FILE}"

echo "==> Done. Verify with:"
echo "    docker compose exec db_suspicious_replica mariadb \\"
echo "        --user=root --password='\${MYSQL_ROOT_PASSWORD}' \\"
echo "        -e 'SHOW SLAVE STATUS\\G'"
echo
echo "    Look for: Slave_IO_Running=Yes, Slave_SQL_Running=Yes, Seconds_Behind_Master=0"
