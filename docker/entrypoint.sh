#!/bin/sh
# Container entrypoint.
#
# Chalk keeps its config, database and keys in one directory. A fresh container
# has an empty volume, so the first start has to initialise it — otherwise
# `docker run chalk` fails with "no configuration file", which is a poor first
# impression for a product whose pitch is "one binary, no dependencies".
#
# Initialisation is guarded on the config file existing rather than on `chalk
# init` being safe to repeat: a second init generates a new master encryption
# key, and that key is what every stored credential is sealed with. Running it
# over a live volume would leave a database nobody can read.
#
# CHALK_DATA_DIR is honoured by passing it through as a flag. The binary reads
# no environment variable of its own, so the alternative would be an env var
# that looks configurable and silently does nothing.
set -eu

DATA_DIR="${CHALK_DATA_DIR:-/var/lib/chalk}"
CONFIG="$DATA_DIR/chalk.toml"

if [ ! -f "$CONFIG" ]; then
    echo "chalk: no configuration at $CONFIG — initialising"
    chalk init --data-dir "$DATA_DIR"
    echo ""
    echo "chalk: initialised. The admin password above is shown once."
    echo "chalk: change it from Settings after signing in."
    echo ""
fi

exec chalk --config "$CONFIG" "$@"
