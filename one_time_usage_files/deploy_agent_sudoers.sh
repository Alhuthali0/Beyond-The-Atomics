#!/bin/bash
# deploy_agent_sudoers.sh
# Safely grants the current agent user passwordless sudo access for non-interactive tests.

AGENT_USER=$(whoami)
SUDOERS_FILE="/etc/sudoers.d/bas-agent"

echo "[*] Granting passwordless sudo to user: $AGENT_USER"

# Create a temporary file to validate syntax
echo "$AGENT_USER ALL=(ALL) NOPASSWD: ALL" > /tmp/bas-agent-sudoers

# Use visudo to check syntax before applying
if sudo visudo -cf /tmp/bas-agent-sudoers; then
    echo "[+] Syntax valid. Applying to $SUDOERS_FILE"
    sudo cp /tmp/bas-agent-sudoers "$SUDOERS_FILE"
    sudo chmod 440 "$SUDOERS_FILE"
    echo "[+] Sudoers update complete."
else
    echo "[X] Error: Invalid sudoers syntax generated. Aborting."
    exit 1
fi

rm /tmp/bas-agent-sudoers
