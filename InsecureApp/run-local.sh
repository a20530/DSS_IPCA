#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python -m venv .venv
fi

.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r requirements-local.txt

export FLASK_ENV=development
export FLASK_DEBUG=1
export FLASK_APP=iwa

exec .venv/bin/flask run --host 127.0.0.1 --port 5000
