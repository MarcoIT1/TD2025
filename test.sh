#!/usr/bin/env bash
set -e

echo "Hello from Azure Custom Script Extension! $(date)" | sudo tee /var/tmp/azure-test.txt