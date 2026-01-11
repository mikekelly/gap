#!/bin/bash
set -e

DATA_DIR="/var/lib/acp"

# Check if the data directory is a proper mount point
# This prevents running with ephemeral storage where secrets would be lost
if ! mountpoint -q "$DATA_DIR" 2>/dev/null; then
    # Allow override for testing/ephemeral use cases
    if [ "$ACP_ALLOW_EPHEMERAL" = "I-understand-secrets-will-be-lost" ]; then
        echo "WARNING: Running without persistent storage. Secrets will be lost when container stops." >&2
    else
        echo "ERROR: $DATA_DIR is not a mounted volume." >&2
        echo "" >&2
        echo "ACP requires persistent storage for secrets. Without a volume mount," >&2
        echo "your credentials will be lost when the container stops." >&2
        echo "" >&2
        echo "Run with a volume mount:" >&2
        echo "  docker run -v acp-data:/var/lib/acp mikekelly/acp" >&2
        echo "" >&2
        echo "Or with a bind mount:" >&2
        echo "  docker run -v /path/to/acp-data:/var/lib/acp mikekelly/acp" >&2
        echo "" >&2
        echo "For testing only, you can bypass this check with:" >&2
        echo "  docker run -e ACP_ALLOW_EPHEMERAL=I-understand-secrets-will-be-lost mikekelly/acp" >&2
        echo "" >&2
        exit 1
    fi
fi

# Ensure proper permissions on the data directory
if [ ! -w "$DATA_DIR" ]; then
    echo "ERROR: $DATA_DIR is not writable by the acp user." >&2
    echo "Ensure the volume has correct permissions (owned by UID 999 or world-writable)." >&2
    exit 1
fi

exec "$@"
