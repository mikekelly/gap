# Ideas

Raw thoughts, not yet evaluated.

- mitmproxy + gap to provide transparent proxy (for monitoring) and explicit proxy (for credential injection)
    - docker compose networking isn't suitable for this, look into kata and apple containers (https://github.com/mcrich23/container-compose)
- certs from boot (linux user place in shared dir?)
- In memory SurrealDB that flushes to disk ecrypted using secret stored in keychain (might be possible with SurrealDB + RocksDB)
- **Disk-encrypted credential storage (macOS)**: Store credentials on disk encrypted with a single master key stored in keychain. Reduces keychain prompts from N (one per credential) to 1 (just the master key). Would make Homebrew distribution much more usable for users with multiple plugins.
- Analaytics (overall usage, failures, etc)
- Activity log
- Policy plugins (rate limiting, rogue agent detection, etc)
- Transparent proxy mode (capture and forward all HTTP(S) traffic) related: SOCKS proxy
    - This is likely dependent on in memory database for recording and analysing activity (occasional flush to disk)
- Plugins that can initiate and handle OAuth dance when installed
    - Look at most popular mcp servers with OAuth to see how much variance in implementation there is (generic implementation vs per plugin implementation)
- Plugin authoring guide documentation
- Drop-in wrappers for common http libraries that handle GAP proxying transparently (exa-mcp-server fork would be a good test candidate)
