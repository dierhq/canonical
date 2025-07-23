#!/bin/bash

# Variables
USER="root"
PASS="dierHQ@321a"
HOST="167.71.199.164"

# Run remote command using sshpass
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$HOST" "echo 'Hostname:'; hostname; echo 'Date:'; date"
