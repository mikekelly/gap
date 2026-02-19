# Ideas

Raw thoughts, not yet evaluated.

- crypto API for the plugin runtime (mTLS, HTTP signature, etc)(mTLS, HTTP signature, etc)
    - v1: HTTP signature support
        - set private key as credential (what encoding?)
        - how do we ensure the representation of the headers signed in js matches the rust client making onward request? should we instead just return the key specifically for this scheme? counter argument: if we don't take the effort to make this work for http signing then it can't work for other non-standard schemes.

- Test request panel in the macos gui

- Plugins that can initiate and handle OAuth dance when installed
    - Look at most popular mcp servers with OAuth to see how much variance in implementation there is (generic implementation vs per plugin implementation)

- Basic plugin template for static value header injection

- Scoped tokens
    - Do plugins define scopes?

- What happens when plugins conflict on the host pattern?
- Is the pattern match host only or can a plugin match on the host + path template?

- Performance, resource usage, load testing.

- Support for mTLS on the outbound
    - the key and the cert need to be returned by the plugin to the rust client making onward request?

- Transparent proxy mode (capture and forward all HTTP(S) traffic) related: SOCKS proxy
    - This is likely dependent on in memory database for recording and analysing activity (occasional flush to disk)
- Policy plugins (rate limiting, rogue agent detection, etc)

- Analaytics (overall usage, failures, etc)

- using-gap skill
- developing-gap-plugins skill
- some kind of testing harness tool for plugins for developing gap plugins
- Drop-in wrappers for common http libraries that handle GAP proxying transparently (python, TS, Java, ruby, elixir)

- macOS app: Keychain prompt on first launch
    - gap-server uses traditional keychain (kSecUseDataProtectionKeychain=false) which triggers ACL password prompts
    - Options: (a) use Data Protection Keychain with proper entitlements (requires keychain-access-groups), (b) "Always Allow" prompt education, (c) pre-authorize during install

- Make MacOS app capable of connecting to other gap servers which aren't default localhost + ports. Needs consideration; how can we package up root certs and endpoints for this? Install to ~/.gap/external-servers/
