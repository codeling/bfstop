#!/usr/bin/env bash
#
# Starts a database server in a docker container named "db" (for CI) and
# waits until it accepts connections. Writes DB_TYPE and DB_USER for
# install-joomla.sh to $GITHUB_ENV (if set).
#
# Environment:
#   DB_IMAGE   docker image, e.g. mysql:8.4, mariadb:11.4 or postgres:17
#   DB_HOST, DB_PASS, DB_NAME
set -euo pipefail

: "${DB_IMAGE:?}" "${DB_HOST:?}" "${DB_PASS:?}" "${DB_NAME:?}"

case "$DB_IMAGE" in
	postgres:*)
		docker run -d --name db -p 5432:5432 -e POSTGRES_PASSWORD="$DB_PASS" -e POSTGRES_DB="$DB_NAME" "$DB_IMAGE"
		db_type=pgsql
		db_user=postgres
		ready() { PGPASSWORD="$DB_PASS" psql -h "$DB_HOST" -U postgres -d "$DB_NAME" -c 'SELECT 1' > /dev/null 2>&1; }
		;;
	mysql:*|mariadb:*)
		docker run -d --name db -p 3306:3306 -e MYSQL_ROOT_PASSWORD="$DB_PASS" -e MYSQL_DATABASE="$DB_NAME" "$DB_IMAGE"
		db_type=mysqli
		db_user=root
		ready() { mysql -h "$DB_HOST" -uroot -p"$DB_PASS" -e 'SELECT 1' "$DB_NAME" > /dev/null 2>&1; }
		;;
	*)
		echo "Unsupported database image: $DB_IMAGE" >&2
		exit 1
		;;
esac

if [ -n "${GITHUB_ENV:-}" ]; then
	echo "DB_TYPE=$db_type" >> "$GITHUB_ENV"
	echo "DB_USER=$db_user" >> "$GITHUB_ENV"
fi

for _ in $(seq 90); do
	if ready; then
		echo "Database ready (DB_TYPE=$db_type, DB_USER=$db_user)"
		exit 0
	fi
	sleep 2
done
docker logs db
exit 1
