# Homebrew Tap Plan

## Goal
Create `mikekelly/homebrew-acp` tap that installs binaries from `mikekelly/acp` releases.

## User Experience (end result)
```bash
brew tap mikekelly/acp
brew install acp-server
brew services start acp-server  # optional: use Homebrew's service management
# OR
acp-server install              # use built-in service management
```

## Prerequisites
1. GitHub releases on `mikekelly/acp` with signed/notarized binaries
2. Binaries for both architectures: `acp-darwin-arm64`, `acp-darwin-x86_64`

---

## Phase 1: Release Artifacts in mikekelly/acp

Before the tap works, we need release binaries. Create a release workflow:

### 1.1 Build release binaries
```bash
# In mikekelly/acp repo
cargo build --release
```

### 1.2 Sign and notarize
```bash
./scripts/macos-sign.sh --production
./scripts/macos-notarize.sh target/release/acp
./scripts/macos-notarize.sh target/release/acp-server
```

### 1.3 Create GitHub release
- Tag: `v0.1.0`
- Assets:
  - `acp-darwin-arm64.tar.gz` (contains `acp` and `acp-server`)
  - `acp-darwin-x86_64.tar.gz`
  - `acp-linux-x86_64.tar.gz` (future)

---

## Phase 2: Create homebrew-acp Repository

### 2.1 Directory structure
```
~/code/homebrew-acp/
├── README.md
├── Formula/
│   └── acp-server.rb
└── .github/
    └── workflows/
        └── test.yml  # optional: test formula on PR
```

### 2.2 Formula file (Formula/acp-server.rb)
```ruby
class AcpServer < Formula
  desc "Agent Credential Proxy - secure credential management for AI agents"
  homepage "https://github.com/mikekelly/acp"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mikekelly/acp/releases/download/v0.1.0/acp-darwin-arm64.tar.gz"
      sha256 "PLACEHOLDER_ARM64_SHA256"
    else
      url "https://github.com/mikekelly/acp/releases/download/v0.1.0/acp-darwin-x86_64.tar.gz"
      sha256 "PLACEHOLDER_X86_64_SHA256"
    end
  end

  def install
    bin.install "acp"
    bin.install "acp-server"
  end

  service do
    run [opt_bin/"acp-server"]
    keep_alive true
    log_path var/"log/acp-server.log"
    error_log_path var/"log/acp-server.err"
  end

  test do
    system "#{bin}/acp-server", "--version"
  end
end
```

### 2.3 README.md
```markdown
# Homebrew ACP

Homebrew tap for [ACP (Agent Credential Proxy)](https://github.com/mikekelly/acp).

## Installation

```bash
brew tap mikekelly/acp
brew install acp-server
```

## Start as background service

```bash
brew services start acp-server
```

## Uninstall

```bash
brew services stop acp-server
brew uninstall acp-server
brew untap mikekelly/acp
```
```

---

## Phase 3: Publish

### 3.1 Create GitHub repo
```bash
cd ~/code/homebrew-acp
git init
git add .
git commit -m "Initial formula for acp-server"
gh repo create mikekelly/homebrew-acp --public --source=. --push
```

### 3.2 Update formula on new releases
When releasing a new version of acp:
1. Build and sign binaries
2. Create GitHub release with assets
3. Get SHA256 of each tarball: `shasum -a 256 *.tar.gz`
4. Update formula with new version and SHA256s
5. Push to homebrew-acp

---

## Phase 4: Automation (optional)

### 4.1 Release workflow in mikekelly/acp
GitHub Action that:
1. Builds binaries for all platforms
2. Signs and notarizes (requires secrets for Apple credentials)
3. Creates release with assets
4. Triggers update in homebrew-acp repo

### 4.2 Auto-update workflow in homebrew-acp
GitHub Action that:
1. Watches for new releases in mikekelly/acp
2. Downloads assets, computes SHA256
3. Updates formula
4. Creates PR or auto-commits

---

## Tasks

1. [ ] Create release binaries for mikekelly/acp (manual first time)
2. [ ] Create ~/code/homebrew-acp directory structure
3. [ ] Write Formula/acp-server.rb with correct SHA256s
4. [ ] Write README.md
5. [ ] Push to GitHub as mikekelly/homebrew-acp
6. [ ] Test: `brew tap mikekelly/acp && brew install acp-server`
7. [ ] Test: `brew services start acp-server`

## Open Questions

- Do we want a single formula (`acp-server`) or separate (`acp` CLI + `acp-server`)?
- Should we support Linux in the formula? (Linuxbrew exists)
- Automate releases with GitHub Actions?
