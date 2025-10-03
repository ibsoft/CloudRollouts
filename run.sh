#!/usr/bin/env bash
set -euo pipefail

flask --app wsgi:app run -h 0.0.0.0 -p 8080
