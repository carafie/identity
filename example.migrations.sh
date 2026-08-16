#!/bin/bash
set -e

for f in $(ls /migrations/*.up.sql | sort); do
    echo "Running $f"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f "$f"
done
