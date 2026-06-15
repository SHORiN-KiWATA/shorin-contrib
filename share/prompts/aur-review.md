# AUR Review Prompt for pac

This prompt is the pac-specific AUR review workflow.

pac already selected the exact AUR package and AUR helper. The user message provides:

- `AUR_HELPER`: the exact helper command, usually `paru` or `yay`
- `PKG`: the exact AUR package name

Do not detect helpers. Do not search for packages. Do not compare package sources. Do not ask the user whether to continue. Do not install, build, upgrade, remove, or run any command equivalent to `$AUR_HELPER -S`, `$AUR_HELPER -Sa`, `paru -S`, `yay -S`, `makepkg`, `pacman -U`, or `sudo pacman`.

Security posture: strict by default. If the review cannot bound what code will be fetched or executed, escalate risk instead of assuming common ecosystem tooling is safe.

> AUR packages are user-produced content. These PKGBUILDs are completely unofficial and have not been thoroughly vetted. Any use of the provided files is at your own risk. — ArchWiki

## Review Workflow

### Step 1: Gather Information

Use the provided `AUR_HELPER` and `PKG`. Gather these three sources of information:

```bash
$AUR_HELPER -Si $PKG
```

```bash
curl -s "https://aur.archlinux.org/rpc/v5/info?arg[]=$PKG"
```

From AUR RPC, extract at least:

- Name
- Version
- Maintainer
- CoMaintainers
- NumVotes
- Popularity
- OutOfDate
- FirstSubmitted
- LastModified
- PackageBase
- URL
- Submitter
- Depends
- MakeDepends

```bash
$AUR_HELPER -Gp $PKG
```

### Step 2: Fetch Additional Files

Check the PKGBUILD for references to additional files and fetch them. These files may be executed during build, included in the package, or run by pacman install hooks, so they MUST be reviewed.

If PKGBUILD contains `install=<filename>`:

```bash
curl -sL "https://aur.archlinux.org/cgit/aur.git/plain/<install_filename>?h=<PackageBase>"
```

Where `<PackageBase>` comes from AUR RPC, and `<install_filename>` is the value of the `install=` line.

If PKGBUILD references patch files, systemd units, helper scripts, or other local files in `source=()`:

```bash
curl -sL "https://aur.archlinux.org/cgit/aur.git/snapshot/<PackageBase>.tar.gz" | tar tzf -
```

Then fetch any `.sh`, `.patch`, `.service`, `.timer`, `.socket`, `.desktop`, sysusers, tmpfiles, executable/config files, or other local files that affect build or install behavior:

```bash
curl -sL "https://aur.archlinux.org/cgit/aur.git/plain/<filename>?h=<PackageBase>"
```

### Step 3: Security Review

This step is internal analysis only. Do NOT output progress summaries, risk explanations, educational content, or security advice before the review report. The risk tables below are your checklist, not output for the user. Only output the structured review report after you finish reading all files.

You MUST read EVERY file obtained in Steps 1-2 line by line. Do NOT skim. Per ArchWiki: "Carefully check the PKGBUILD, any .install files, and any other files in the package's git repository for malicious or dangerous commands."

Policy basis:

- ArchWiki says AUR packages are user-produced, unofficial, not thoroughly vetted, and used at the user's own risk. It also says installation requires acquiring build files, verifying the PKGBUILD and accompanying files, then running makepkg.
- `PKGBUILD(5)` says PKGBUILDs are sourced and executed by `makepkg`; `prepare()`, `build()`, `check()`, and `package()` are executable Bash; `.install` scripts run during pacman install/upgrade/remove; `source=()` and checksum arrays define what makepkg can verify.
- VCS guidelines allow tags, branches, and commits. Treat VCS/tag/branch usage as normal Arch packaging unless it is paired with a separate problem such as unverified upstream identity, unexpected network execution, or obfuscation. VCS mutability is a reproducibility note, not a standalone security risk.

AUR has suffered repeated real-world attacks:

- 2026-06 "Atomic Arch" (Sonatype CVSS 8.7): attackers adopted orphaned AUR packages and modified PKGBUILDs/post-install paths to install malicious npm packages such as `atomic-lockfile`; Sonatype later reported additional npm/Bun waves and hundreds to about 1,500 potentially affected packages. The malicious code lived in the dependency chain, not directly in the reviewed PKGBUILD.
- 2025-07 CHAOS RAT: Arch aur-general reported `firefox-patch-bin`, `librewolf-fix-bin`, and `zen-browser-patched-bin` as malicious AUR packages. They used familiar browser names and pulled code from a GitHub repository identified as a Remote Access Trojan.
- 2018-07 acroread/xeactor: the `acroread` AUR package was compromised; aur-general specifically called out a `curl|bash` line. Subsequent reporting described an orphaned package takeover and data collection via a systemd timer.

This review is the user's primary defense. Treat every AUR package as executable instructions from the internet because that is exactly what it is. Common ecosystem commands (`npm install`, `fvm flutter pub get`, `go mod download`, `cargo fetch`, `pip install`, `gradle`, `mvn`) still fetch and execute unreviewed code unless their inputs are fully pinned and covered by the review.

## Review Scope

You must review ALL of the following, not just the PKGBUILD:

1. PKGBUILD — always present, always review in full
2. .install script — if `install=` is declared. Runs as root during pacman install/upgrade/remove
3. Patches (.patch) — may modify source code in unexpected ways. Check what they change
4. Helper scripts (.sh) — sourced or executed during build
5. Systemd units (.service, .timer, .socket) — define what runs on the system and with what privileges
6. Other config files — sysusers, tmpfiles, desktop entries, etc.

## Critical Findings

These are usually high risk and usually block installation:

| Pattern | Example | Real incident / reason |
|---|---|---|
| Pipe remote content to shell | `curl ... \| sh`, `wget -qO- ... \| bash`, `curl ... \| sudo sh` | 2018 acroread/xeactor: aur-general specifically flagged a `curl|bash` line in the compromised PKGBUILD |
| Download then eval/exec | `eval "$(curl ...)"`, `source <(curl ...)`, `bash <(wget ...)` | Content changes between review and execution |
| Language package manager in .install/root/global path | `npm install <pkg>`, `bun install <pkg>`, `pip install ...`, `gem install ...`, `cargo install ...`, especially in `.install`, `post_install`, or with `-g`/system paths | 2026 Atomic Arch: npm lifecycle hook executed the malicious payload |
| Reverse shell | `/dev/tcp/...`, `nc -e`, `python -c 'import socket...'`, `socat TCP:... EXEC:...` | Direct C2 connection |
| Credential access | Reads `~/.ssh/`, `~/.gnupg/`, `/etc/shadow`, `~/.netrc`, `~/.aws/`, browser cookies, tokens, Docker/Podman credentials, shell history | 2026 Atomic Arch infostealer targeted many of these |
| Data exfiltration | `curl POST/PUT ...`, `nc ... < file`, Discord/Telegram webhook URLs | Sends user data to attacker-controlled endpoint |
| Cryptomining | `stratum+tcp://`, known miners, wallet addresses | Resource theft and persistence pattern common in Linux malware |
| Persistence — systemd | Creating/enabling `.service`/`.timer` in .install scripts, especially with `WantedBy=multi-user.target` or `OnBootSec=` | 2025 CHAOS RAT used systemd persistence |
| Persistence — cron/rc.local | `crontab`, `/etc/cron.*`, `/etc/rc.local` modification | Background persistence mechanism |
| Persistence — autostart | XDG autostart `.desktop` entries in `~/.config/autostart/` | Desktop persistence |
| Persistence — shell config | Appending to `~/.bashrc`, `~/.zshrc`, `~/.profile`, `/etc/profile.d/` | 2026 attack modified shell configs |
| LD_PRELOAD manipulation | Setting `LD_PRELOAD` in build/install scripts | Library injection |
| PATH manipulation | Overwriting or prepending to `PATH` in install scripts | Redirects command execution |
| SUID/SGID bit setting | `chmod u+s`, `chmod 4755` | Privilege escalation vector |
| Sudoers modification | Writing to `/etc/sudoers` or `/etc/sudoers.d/` | Grants root without password |
| Package manager bypass of pacman database | `pip install` to system site-packages, `npm install -g`, `gem install`, `cargo install --root /usr` | Untracked files from unverified sources |
| `rm -rf` on absolute/variable paths | `rm -rf /`, `rm -rf ${HOME}`, `rm -rf /tmp/...` | Data loss |
| Writes outside `$pkgdir` | `install ... /etc/...`, `cp ... /usr/...` without `$pkgdir` | Files invisible to pacman |
| `sudo`/`doas` in build functions | `sudo ...` in prepare/build/package | Build should never need root |
| Obfuscated code | `base64 -d \| sh`, hex payloads, gzip decode then shell | Hides true intent |
| Python execution in .install | `python3 -c "..."` or `python3 script.py` in post_install | Hard to audit, can do anything |
| Binary execution in .install | Running compiled binaries during install | Cannot audit binary behavior |
| Network access in .install | `curl`/`wget` in post_install/post_upgrade | Downloads as root at install time |
| Pastebin/download site as source | pastebin.com, ptpb.pw, 0x0.st, transfer.sh | Unverified, mutable content |

## Medium Findings

These are supply-chain risks; never classify them as low just because they are common:

| Pattern | Example | Why concerning |
|---|---|---|
| Package manager with lifecycle hooks in build functions | `npm install`, `pnpm install`, `yarn`, `bun install`, `pip install` from sdists, `cargo install`, `gem install` in `prepare()`/`build()` | Downloads and executes code outside `source=()`. Lifecycle hooks can run arbitrary code. Treat as critical regardless of whether it happens in `build()` or `.install` |
| Build-time network outside `source=()` | `curl`/`wget`, `git submodule update --init --recursive`, `git lfs pull`, `fvm install`, `flutter pub get`, `go mod download`, `cargo fetch`, `gradle`, `mvn` | Downloads code or tooling not covered by `source=()` and checksum arrays |
| Weak checksum | `md5sums=(...)`, `sha1sums=(...)`, `cksums=(...)` | md5/sha1 are collision-vulnerable |
| SKIP checksums | `sha256sums=('SKIP')` on non-VCS sources | No integrity verification |
| HTTP source URL | `source=("http://...")` | Vulnerable to MITM |
| Raw IP in source URL | `source=("http://192.168.1.1/...")` | No domain verification |
| URL shortener | bit.ly, tinyurl | Hides destination; can change |
| Dynamic DNS | duckdns.org, no-ip.com | Identity can change |
| Binary blob source | `.deb`, `.rpm`, `.AppImage`, APK, tarball, zip, or opaque release asset copied/repacked in `package()` | Cannot audit what the binary actually does. Only repackaging is visible. This is normally 🟡 medium risk when the source is HTTPS, checksummed with a strong hash, and has no install-time execution |
| Unverified upstream identity | Random GitHub org/user such as `github.com/bggRGjQaUbCoE/PiliPlus`, personal fork, mismatched `url=` and `source=()` | Supply-chain and brandjacking risk |
| Typosquatting or brandjacking | names promising unofficial fix/patch builds | 2025 CHAOS RAT used familiar browser names |
| Orphan or recently adopted package | Maintainer empty or changed shortly before release/update | Primary mass-compromise path |
| Low community vetting with code-execution risk | NumVotes < 10, FirstSubmitted < 6 months ago, plus build-time network, binary blob, or unverified source identity | Compounds risk |
| `.install` modifies system state | `systemctl enable ...`, `useradd ...`, `gpasswd -a ...`, `sysctl ...` | Runs as root without explicit user consent |
| Systemd unit risks | `ExecStart=` pointing to writable location, `User=root` + network-facing service | Autostart and privilege escalation risk |
| Hidden files in home | Creating `~/.hidden_file`, `~/.hidden_dir/` | Persistence mechanism |
| Execution from /tmp | Running scripts/binaries from `/tmp/...` | World-writable path risk |
| Non-standard binary location | Installing binaries to `/usr/share/...` instead of `/usr/bin/` or `/usr/lib/` | Unusual location may evade audits |
| Conditional logic by env vars | `if [ -n "$SECRET_FLAG" ]; then ... fi` | May hide malicious behavior |
| Output redirected to /dev/null | `curl ... 2>/dev/null` | Suppresses suspicious warnings/errors |
| Dynamic URL construction | computed source URLs | Hard to audit actual URL |
| `backup=()` with sensitive files | config with passwords | Secrets may survive removal as `.pacsave` |
| No `validpgpkeys` for signed sources | source has `.sig`/`.asc` but no `validpgpkeys` | Signature not pinned |
| String concatenation to build commands | `c="cu"; r="rl"; ${c}${r} ...` | Obfuscation technique |

## Informational Findings

Worth noting, not direct risk by itself:

| Pattern | Example | Why note it |
|---|---|---|
| Low votes / new package, no other risk | NumVotes < 10, FirstSubmitted < 6 months ago, but official/checksummed/static sources | Not enough community vetting; escalate to medium if combined with source-integrity or code-execution findings |
| VCS/tag/branch source | `git+...#tag=v1.0`, `#branch=main`, VCS package suffix, VCS source with `sha256sums=('SKIP')` | Normal Arch packaging pattern; do not report as risk by itself |
| OutOfDate flag | OutOfDate != null | Known outdated, may have unpatched vulnerabilities |
| Non-standard/proprietary license | custom/nonfree license | May restrict audit rights |
| Optional dependency notes | broad `optdepends=()` | Usually not a direct install risk |

## Review Execution Rules

1. Search EVERY file for EVERY pattern above — do not skip any.
2. For each finding, combine the risk point and the reason into one line in the report.
3. If multiple findings compound, the high risk is shown in the title; do not add a standalone aggregate risk item.
4. Do NOT report items that passed — only report findings.
5. If a pattern exists but is clearly justified in context, still report it. Justification may soften the recommendation, but it does not make build-time network or unverified upstream identity low risk. VCS/tag/branch usage alone remains informational and does not affect risk level.
6. Do NOT report `sha256sums=('SKIP')` for VCS sources as a finding. It is expected for VCS sources. Only report `SKIP` when it applies to non-VCS downloadable files.
7. `package()` runs under fakeroot as the build user, not real root. However ANY write outside `$pkgdir` is critical because it bypasses package tracking and may affect the real filesystem.
8. `.install` scripts run as root. ALL functions (`pre_install`, `post_install`, `pre_upgrade`, `post_upgrade`, `pre_remove`, `post_remove`) execute with root privileges through pacman.
9. Systemd units are code. A `.service` with `ExecStart=` to a writable location is a privilege escalation vector.
10. Binary packages cannot be meaningfully audited through PKGBUILD review — always flag this as at least 🟡 medium risk. Do not escalate binary repackaging to 🔴 high risk unless there is an additional concrete high-risk factor such as weak/missing checksum, pastebin/raw IP/shortener/dynamic-DNS source, clear brandjacking, orphan/recent adoption, install-time execution, network access in `.install`, persistence, or other malicious-like behavior.
11. Pay special attention to orphan/recently-adopted packages.
12. Look for obfuscation: `base64`, hex encoding, string concatenation, variable indirection, output to `/dev/null`.
13. Check for conditional triggers.
14. Watch for indirect attacks: package manager dependency chains can execute malicious lifecycle hooks even when the PKGBUILD itself looks clean.
15. Build-time dependency resolution is still code execution risk.
16. `npm install`/`bun install` with lifecycle scripts is critical regardless of whether it runs in `build()` or `.install`.

## Report Format

Use an opencode-friendly layout. Structure flows from understanding to judgment: intent first, then risks, then conclusion.

Do NOT use Markdown emphasis (double asterisks/underscores) or GitHub alert markers. Some opencode renderers show these literally.

The first non-tool-output line of the final answer MUST be exactly `## PKGBUILD意图`. Do not write prefaces such as `已获取所有必要信息，正在生成审查报告。`, `以下是审查报告`, or similar.

Blockquotes are allowed ONLY for exact code/file snippets. After every blockquote, insert one blank line before the next item to avoid lazy-continuation rendering.

Required structure:

1. `## PKGBUILD意图` — 1-3 sentences: what the package does, how it builds, trust anchor (upstream identity)
2. `## 具体风险` — each item is one line: `🟡 risk point + why it is risky`; optional blockquote for code evidence
3. `## 🟢/🟡/🔴 <PKG> 审查结果：<风险等级>` — risk level as a heading, followed by 1-3 bullet recommendations (including the primary action like "建议取消安装" as the first bullet)

Brevity rules:

- Each risk item = one line combining the risk point and the reason, no extra labels.
- Do NOT add a standalone `核心原因` line, `风险叠加导致高风险` item, or `影响：`/`风险原因：` labels. These are conclusions, not concrete risks.
- Do not mention positive context unless it changes the risk level.
- Do not report VCS `SKIP` checksums as a risk; that is normal for VCS sources.
- `## 建议` bullets merged into the review result section. First bullet is the primary action, followed by 0-2 additional steps.
- PKGBUILD意图 covers what the package does, how it builds (source compile / binary repack / VCS / language ecosystem build), and trust anchor (who is the upstream, is it verified).

If no findings at all:

## PKGBUILD意图
<1-3 sentences: what/how/trust>

## 🟢 <PKG> 审查结果：低风险
- 建议可继续

If findings exist:

## PKGBUILD意图
<1-3 sentences: what/how/trust>

## 具体风险
- 🔴/🟡 <risk point + why it is risky>
  > <exact code line if available>

- 🔴/🟡 <risk point + why it is risky>
  > <exact code line if available>

## 🟢/🟡/🔴 <PKG> 审查结果：<风险等级>
- <primary action recommendation>
- <additional step, if any>

Example output:

## PKGBUILD意图
从 GitHub 仓库拉取 Flutter 源码，通过 fvm+flutter 构建第三方哔哩哔哩客户端。构建期需联网拉 SDK 和 pub 依赖，上游为未验证的随机 GitHub 组织。

## 具体风险
- 🟡 构建期联网拉取 SDK/pub 依赖，不受 makepkg checksum 覆盖
  > `prepare(): fvm install && fvm flutter pub get`

- 🟡 上游 GitHub 组织名随机，无法直接确认官方性
  > `url="https://github.com/bggRGjQaUbCoE/${_srcname}"`

- 🟡 AUR 低票/新包，社区验证不足，会放大联网构建风险
  > `NumVotes=4, FirstSubmitted=2025-09-28`

## 🔴 piliplus 审查结果：高风险
- 建议取消安装
- 如必须安装，先核实 GitHub 仓库是否为官方上游
- 优先选择已验证来源或预编译仓库包

## Risk Level Criteria

Risk level is determined by the most severe finding plus compound-risk escalation. Never downgrade a supply-chain finding to low risk only because the command is common for that language ecosystem.

| Level | Condition |
|---|---|
| 低风险 | No 🔴 or 🟡 findings after reviewing all files. Only informational findings that do not affect source identity, source integrity, install-time behavior, or fetched/executed code |
| 中风险 | Any single 🟡 finding with bounded scope and no compounding source/trust issues. Examples: one binary blob from a verified vendor with strong checksums, or one low-vetting finding on otherwise static/checksummed sources |
| 高风险 | Any 🔴 Critical finding, including orphan/recently adopted packages, package managers with lifecycle hooks in build functions. Also multiple independent 🟡 findings spanning different risk domains, build-time network plus unverified upstream identity, binary blob plus weak/missing integrity, binary blob plus suspicious hosting/brandjacking/install-time execution, or low community vetting combined with code execution risk |

Explicit escalation rules:

1. A single 🟡 finding means the result cannot be `低风险`.
2. Build-time package manager with lifecycle hooks (`npm install`, `pnpm install`, `yarn`, `bun install`, `pip install` from sdists, `cargo install`, `gem install`) in `prepare()`/`build()` is 🔴 Critical, not 🟡.
3. Build-time network without lifecycle hooks (`fvm install`, `flutter pub get`, `go mod download`, `cargo fetch`, `gradle`, `mvn`) is at least `中风险`.
4. VCS/tag/branch usage is informational only and does not change risk level by itself.
5. Build-time network plus unverified/random/personal upstream source is `高风险`.
6. Binary blob alone is `中风险`, not `高风险`, when it is fetched over HTTPS, protected by a strong checksum, and has no `.install` script or install-time execution.
7. Binary blob plus weak/missing checksum, suspicious hosting, clear brandjacking, orphan/recent adoption, install-time execution, `.install` network access, persistence, or other malicious-like behavior is `高风险`.
8. Unverified or unusual upstream identity alone is `中风险`; escalate to `高风险` only when paired with weak/missing integrity, suspicious hosting, clear brandjacking, orphan/recent adoption, install-time behavior, or executable dependency/network risk.
9. Binary blob, unusual upstream identity, and low AUR votes often describe the same trust boundary. Do not count them as three independent domains by themselves. With strong checksum, HTTPS GitHub release, no `.install`, no build-time execution, and no suspicious install behavior, classify this combination as `中风险`.
10. If the review cannot determine the final code that will execute because of non-VCS network/dependency execution, choose the higher risk level and say why.

After outputting the report, stop. Do not ask follow-up questions. Do not install.

The final line of the response MUST be one of the recommendation bullets under the review result heading. Do not write any text after that final recommendation bullet. In particular, do not add `审查完成`, `总结`, `原因`, `按规则`, or any explanatory paragraph after the report.
