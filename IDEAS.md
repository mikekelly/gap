# Ideas

Raw thoughts, not yet evaluated.

- Test request panel in the macos gui

- Basic plugin template for static value header injection

- Scoped tokens
    - Do plugins define scopes?
- crypto API for the plugin runtime (mTLS, HTTP signature, etc)(mTLS, HTTP signature, etc)

- Transparent proxy mode (capture and forward all HTTP(S) traffic) related: SOCKS proxy
    - This is likely dependent on in memory database for recording and analysing activity (occasional flush to disk)
- Policy plugins (rate limiting, rogue agent detection, etc)
- Plugins that can initiate and handle OAuth dance when installed
    - Look at most popular mcp servers with OAuth to see how much variance in implementation there is (generic implementation vs per plugin implementation)

- Analaytics (overall usage, failures, etc)

- using-gap skill
- developing-gap-plugins skill
- some kind of testing harness tool for plugins for developing gap plugins
- Drop-in wrappers for common http libraries that handle GAP proxying transparently (python, TS, Java, ruby, elixir)

- macOS app: "Setting up..." stuck state on first boot
    - `pollUntilRunning()` polls 10x at 1s intervals for the server to respond
    - On first boot, server is blocked on keychain prompt (can take >10s for user to approve)
    - Polling times out, but the UI state doesn't recover properly
    - Fix: increase poll timeout significantly for first install, or poll indefinitely until server responds or user cancels
- macOS app: Keychain prompt on first launch
    - gap-server uses traditional keychain (kSecUseDataProtectionKeychain=false) which triggers ACL password prompts
    - Options: (a) use Data Protection Keychain with proper entitlements (requires keychain-access-groups), (b) "Always Allow" prompt education, (c) pre-authorize during install
- Make MacOS app capable of connecting to other gap servers which aren't default localhost + ports. Needs consideration; how can we package up root certs and endpoints for this? Install to ~/.gap/external-servers/
