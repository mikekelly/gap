# Ideas

Raw thoughts, not yet evaluated.

- Transparent proxy mode (capture and forward all HTTP(S) traffic) related: SOCKS proxy
    - This is likely dependent on in memory database for recording and analysing activity (occasional flush to disk)
- related to above: mitmproxy + gap to provide transparent proxy (for monitoring) and explicit proxy (for credential injection)
    - docker compose networking isn't suitable for this, look into kata and apple containers (https://github.com/mcrich23/container-compose)
- certs from boot (linux user place in shared dir?)
- In memory SurrealDB that flushes to disk ecrypted using secret stored in keychain (might be possible with SurrealDB + RocksDB)
- Analaytics (overall usage, failures, etc)
- Activity log
- Policy plugins (rate limiting, rogue agent detection, etc)
- Plugins that can initiate and handle OAuth dance when installed
    - Look at most popular mcp servers with OAuth to see how much variance in implementation there is (generic implementation vs per plugin implementation)
- using-gap skill
- developing-gap-plugins skill
- some kind of testing harness tool for plugins for developing gap plugins
- Drop-in wrappers for common http libraries that handle GAP proxying transparently (exa-mcp-server fork would be a good test candidate)
