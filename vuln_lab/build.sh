#!/bin/bash
# build.sh – build task41enc and task41dec using the project Makefile.
#
# Usage: bash build.sh
#
# Requires: make, a C11 compiler, OpenSSL 3 development files

set -euo pipefail

make all

echo ""
echo "Build successful."
echo "  ./task41enc   – encrypt a message to text.ct"
echo "  ./task41dec   – decrypt text.ct and print the message"
