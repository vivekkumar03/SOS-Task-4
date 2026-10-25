#!/bin/bash
# build.sh – compile task41enc and task41dec without requiring make.
#
# Usage:
#   chmod +x build.sh
#   ./build.sh
#
# Requires: gcc, libssl-dev

set -euo pipefail

make clean all

echo ""
echo "Build successful."
echo "  ./task41enc   – encrypt a message to text.ct"
echo "  ./task41dec   – decrypt text.ct and print the message"
