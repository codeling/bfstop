# Setup assistant: first run and upgrade from 1.5.2 to 2.0.0

This document plans a setup assistant (wizard) for Brute Force Stop. It
covers both a fresh installation and the update from 1.5.2, with a focus on
the client address behind a proxy, load balancer or CDN. It also records the
decisions taken while planning, including the alternatives that were
rejected and why.

## 1. Background: what changed between 1.5.2 and 2.0.0

### 1.1 Client address and proxies

**1.5.2** had no proxy settings. `helpers/ipaddress.php` looked at these
headers on every request, in this order: `Client-Ip`, `X-Forwarded-For`,
`X-Forwarded`, `X-Cluster-Client-Ip`, `Forwarded-For`, `Forwarded`. It took
the leftmost public address it found and fell back to `REMOTE_ADDR` only if
none of them had one. Any visitor could forge that address.

**2.0.0** uses `REMOTE_ADDR` only, unless proxy support is configured:

- `useProxy` = 1
- a list of trusted proxies in `proxyIpAddress` (addresses or networks no
  wider than /8 for IPv4 or /16 for IPv6)
- one header in `proxyHeaderSource`

The header is then read from right to left, so only the part the trusted
proxies added counts (`IpHelper::clientAddressFromHeader()`).

**The update does not configure anything.** Every 1.5.2 site behind a proxy
ends up with `useProxy=0`:

| Scenario | 1.5.2 used | 2.0.0 after the update, unconfigured | Consequence |
|---|---|---|---|
| **A** Direct, no proxy | `REMOTE_ADDR`, forgeable through headers | `REMOTE_ADDR` | Correct. Old blocks may hold addresses an attacker framed. |
| **B** Reverse proxy or load balancer; the web server doesn't rewrite the address | Leftmost public header entry, usually the real client | **Every visitor counts as the proxy's address** | **Whole-site lockout.** Failed logins of all users add up on one address (defaults: 10 within a week), so the proxy gets blocked. "Full Site" refuses backend requests before routing, so the admin can't get in either. `.htaccess` mode writes the proxy into the file, so Apache refuses everyone. After 3 blocks the block becomes permanent. Allow-list entries stop matching. Every user's successful login makes the proxy address a "known address" of that user. |
| **C** The web server already resolves the address (mod_remoteip, nginx `real_ip`) | `REMOTE_ADDR` = client | Correct | The forwarding headers are still present. Turning `useProxy` on here would be **wrong**. |
| **D** CDN with public edge addresses | Leftmost header entry | Visitors count as rotating CDN edge addresses | Blocks land on edge servers and hit random visitors, possibly the admin. |
| **E** The proxy only sends a header BFStop can't use (e.g. `X-Real-IP` only) | Not read either | Can't be configured | Like B until the proxy or web server configuration changes. |

### 1.2 Other configuration changes

Every 1.5.2 setting was compared with `component/admin/forms/settings.xml`,
`Settings::Defaults` and `plugin/updatescript.php::update()`, as of the
delay removal (#340).

**These need the user to make a decision:**

| Change | Why the user is needed | Step |
|---|---|---|
| `notifyBlockedUser`: a stored `1` meant "for any IP address" in 1.5.2 and now means "only for addresses the user logged in from before". Unblock links also need `$live_site`. | The meaning changes silently. The known-address table is empty after the update, so no unblock mails go out until users log in once. Without `$live_site` the effective value is 0, **and the settings page refuses to save any change** while the stored value is not 0. | 3b |
| `useHtaccess`/`blockEnabled` → `blockMode` (mapped automatically) | Whether the result fits depends on the web server and the proxy. `.htaccess` on nginx never worked and now can't be saved. On Apache, whether the server honours the section is unknown. Behind a proxy (B/D), Apache's `-R` compares with the proxy's address, so the entries do nothing. | 2 |
| `blockEnabled=0` (now "Reporting Only") combined with a 1.5.2 delay | The delay was the site's only protection. #340 removed delays, so the site now has no protection at all. | 2 (required) |
| Legacy `.htaccess` section (`Require all granted`) that the update could not rewrite | **Security:** the old section opened the directory to everyone not blocked. | 2b |
| `emailaddress` is now validated (`;`-separated) | A trailing `;`, a comma or a typo **blocks saving** the settings | Inline panel |
| `htaccessPath` is now validated | An invalid path **blocks saving** | Inline panel |
| Usernames stored in plain text | 1.5.2 stored every username typed, including passwords typed into the username field. `2.0.0.sql` copies them in plain text into `#__bfstop_username_stats`, which is never purged by age. 2.0 hashes new entries that match no account (`unknownUsernameMode=hash`), but not old ones. | 5 (opt-in) |
| `deleteOld`: 1.5.2 sites store `0` (never purge); new installs default to 4 weeks | A privacy choice | 5 |

**A review or summary entry is enough for these:**

- `enabledForOrigin` gains the Web Services API bit; the update already switches it on and says so.
- `blockedMessage` is now filtered as safe HTML. Show a diff only if saving would change it.
- Defaults that change behaviour on upgraded sites:
  - "Distributed Attacks on One Account" adds risk points (default 3) while an account is under attack.
  - Risk scoring is on: a common username or a missing user agent lowers the allowed attempts.
  - IPv6 clients are tracked per /56.
  - The log is pruned after 28 days on the first maintenance run.
  - Responses are no longer delayed (#340).
- The daily maintenance moved to Joomla's Task Scheduler.

**No action needed:** `blockNumber`, `blockDuration`, `checkInterval`,
`maxBlocksBefore` (1.5.2's option "6" stored 5), `notifyBlockedNumber`,
`notifyFailedNumber`, `notifyRemainingAttempts`, `notifyUsePasswordReminder`,
`blockedMsgShowIP`, `logLevel`, `useHttpError`, the user and group
notification fields, and the permissions (same assets, now a tab of the
settings page). The 1.x delay settings are removed by the update (#340) and
no longer block saving.

## 2. Activation model

The system plugin only runs once its address handling is known to be right.

| Situation | Plugin state | What the admin sees |
|---|---|---|
| **Fresh install** | **Disabled.** `install()` no longer enables it. The auto-enable (`26527dd`) was never released; 1.5.2 also installed disabled. | "Brute Force Stop is installed but not active yet. Run the setup assistant to activate it." |
| **Upgrade through the browser, no proxy signals** (A or C) | Stays enabled | A strong pointer to the assistant, which doesn't gate anything here |
| **Upgrade through the browser, proxy signals** (B, D or E) | **Disabled during the update** | Error-level message: "Brute Force Stop has been **disabled**: your site appears to be behind a proxy, load balancer or CDN, and BFStop would block the proxy's address, which means everyone. It stays disabled until the setup assistant has been completed." |
| **Upgrade from the command line** | Disabled if Joomla's "Behind Load Balancer" (`behind_loadbalancer`) is on, otherwise stays enabled | The console output gives the assistant's URL and the console commands |

**Activation.** The assistant's last step, "Activate protection", enables the
system plugin once the required steps are done:

1. The proxy step is confirmed. For A or C, the admin confirms there is
   nothing to configure. For B or D, the dry-run preview showed the admin's
   own address and the admin confirmed it.
2. No stored setting blocks saving.
3. The blocking mode fits the web server.

Optional steps do not hold activation back.

**Gaps that remain:**

- **Command-line upgrade, proxy present, "Behind Load Balancer" off:** the
  update has no request to inspect, so the plugin stays enabled and the
  lockout risk remains. Mitigations: the console output, the
  post-installation message, the quick icon, and the proxy warning in the
  block mail.

  This gap can't be closed by having the plugin disable itself later, when
  a visitor's request shows proxy signals, because such signals can be
  forged. With nginx real-IP recursion (`set_real_ip_from 10.0.0.0/8;
  real_ip_recursive on;`), a request carrying `X-Forwarded-For: 10.66.66.66`
  ends up with `REMOTE_ADDR` set to that forged private address plus a
  forwarding header, so one forged request could switch BFStop off. The
  plugin is therefore only ever disabled during the update itself, based on
  the request of the admin running it, never by a later request.
- **False positive:** an admin behind a corporate proxy that adds
  `X-Forwarded-For` gets the plugin disabled unnecessarily. The message
  appears on the update screen, and the proxy step clears it quickly.
- **Enabling the plugin by hand in the Plugin Manager stays possible.** That
  is an explicit admin action. The banner and the quick icon keep saying
  setup is not complete.
- **While the plugin is disabled:** blocks stored in the database are not
  enforced and failed logins are not recorded. Existing `.htaccess` entries
  still apply. The unblock page and the maintenance task keep working,
  because neither needs the system plugin.

## 3. Assistant architecture

- **One assistant, two modes:** `install` and `upgrade`. The steps that only
  make sense after an upgrade appear only in `upgrade` mode. It can be re-run
  later from the settings page (toolbar button "Setup assistant") and the
  proxy step on its own ("Re-run proxy check" in the proxy section).
- **View:** `index.php?option=com_bfstop&view=setup`, restricted to users
  with `core.admin` on com_bfstop, like the settings page. Every task is a
  token-checked POST.
- **State:** one row, `setup`, in `#__bfstop_state` (JSON):
  - `mode` (`install`/`upgrade`) and `from` (the version updated from)
  - status per step: `pending`, `done` or `skipped`
  - why the update disabled the plugin, and the detected scenario. Only the
    scenario and the header names are stored, never the admin's address.
  - whether the update removed delays that were in use, and whether the
    `.htaccess` section could not be rewritten
  - the confirmed proxy fingerprint and the dismissed mismatches
  - `completed`: when activation happened
- **Applying a step:** always through `SettingsModel::save()`, so the existing
  validation, action log, nginx file sync and `.htaccess` clean-up all run.
  Steps can be applied one at a time.
- **Inline panel for stored values that block saving.**
  `SettingsModel::validate()` checks the whole form, so a leftover value in an
  unrelated field would stop any step from saving. Each step shows the
  blocking values, found by running the settings form's own validation on the
  stored settings (no second list of rules). The proposed fixes are saved
  together with the step. Cases known today:
  - an invalid email list
  - an invalid `htaccessPath`
  - `.htaccess` mode on nginx
  - unblock mails switched on without `$live_site`
  - `riskMinBlockNumber` above `blockNumber`
- **Every step follows the same pattern:** detect → recommend → preview →
  user confirms → apply → verify.
- **"Use the defaults" quick path** on every step, so a site with no proxy is
  done in about two clicks.

### 3.1 Entry points

1. **Install or update message** (plugin `postflight()`). It replaces
   `UPDATE_2_0_0_HINT` and `UPDATE_2_0_0_API_HINT` with one message:
   "Action required: open the setup assistant", with a button. It is
   error-level when the update disabled the plugin. The other update
   messages (migration failure, `.htaccess` not rewritten, delays removed)
   stay as they are.
2. **A Joomla post-installation message** (com_postinstall), whose condition
   is "setup not completed".
3. **Quick icon** (section 8).
4. **Banners on every BFStop backend view** (section 6).

## 4. Steps

| # | Step | Install | Upgrade | Required for activation |
|---|---|---|---|---|
| 0 | **Overview.** Upgrade: what the update already did (settings moved, `blockMode` mapped, API switched on, addresses canonicalised, `.htaccess` section rewritten or not, delays removed, maintenance scheduled). Install: a short welcome. | ✓ | ✓ | – |
| 1 | **Proxy / load balancer** (section 5) | ✓ | ✓ | **yes** |
| 1b | **Clean-up after the proxy fix:** lift blocks of the proxy address(es) created since the update, purge their failed logins, offence history (`#__bfstop_offence`) and known-address rows; flag allow-list entries that contain a trusted proxy (adding the proxy to the allow list is a common workaround, and it exempts everyone from protection) | – | ✓ when B/D | – |
| 2 | **Blocking mode and web server.** Run `HtaccessCheckHelper` inline. nginx → "Full Site", plus the optional nginx deny file and its `include` snippet. LiteSpeed → warning. `.htaccess` behind a proxy (B/D) → recommend "Full Site" or mod_remoteip. "Reporting Only": confirm it is intended. **Upgrade: "Reporting Only" with a 1.5.2 delay → flag that the site is now unprotected and recommend "Login Only" or "Full Site".** | ✓ | ✓ | **yes** (the mode must fit the server) |
| 2b | **Legacy `.htaccess` section:** show the file, the replacement section and a retry button (`HtaccessHelper::hasLegacySection()` / `upgradeFormat()`) | – | ✓ when present | – |
| 3 | **Notifications:** address(es), user or group, unblock mails, and the `$live_site` line (existing `liveSiteNote()`) with a "check again" button. `configuration.php` is never written. | ✓ | ✓ | – |
| 3b | **Changed meaning of `notifyBlockedUser`=1.** Choose between "known addresses only" (recommended), "any address" (needs `$live_site`; explains the mail-flood risk) and off | – | ✓ when ≠0 | – |
| 4 | **Protected parts:** frontend, backend, API, with "N users have API tokens" as context | ✓ | ✓ | – |
| 5 | **Privacy:** `deleteOld` choice (shows the row count and the oldest entry); **opt-in** hashing of old usernames that match no account (see below) | – | ✓ | – |
| 6 | **Rate limiting** (replaces the removed delays; see below) | summary only | ✓ when delays were in use | – |
| 7 | **Scheduler:** status of the task plugin, the task and the Task Scheduler, with links | ✓ | ✓ | – |
| 8 | **Summary and activation:** what changed, changed defaults, the reminder (section 5.5), the Joomla consistency hint (section 5.6), and "Activate protection" (enables the system plugin; recorded in the action log) | ✓ | ✓ | – |

**Hashing old usernames (step 5)** runs in batches with progress, over
`#__bfstop_failedlogin` and `#__bfstop_username_stats`:

- It skips usernames that belong to an account or are on the common-username
  list, and hashes the rest with `UsernameHelper::forStorage()` and the site
  secret.
- When two rows of `#__bfstop_username_stats` end up with the same hash, they
  are merged: attempts are added, the earliest and the latest time are kept.
- It mentions that the log file also holds usernames, and offers to clear it.

**Rate-limiting guidance (step 6)** depends on the proxy result from step 1:

- **A (no proxy):** the web server's rate limiting works as described in the
  README (nginx `limit_req`, mod_evasive, mod_qos, fail2ban).
- **B/D (behind a proxy or CDN):** the web server only sees the proxy's
  address, so per-address limits throttle every visitor at once, and fail2ban
  would ban the proxy. Rate-limit at the proxy or CDN instead, or set up the
  real-IP module first (which makes it scenario C).
- **C:** works, using the address the real-IP module sets.

## 5. The proxy step

### 5.1 Detection

All of it runs on the admin's own backend request, plus the database:

1. Forwarding headers present (the supported ones, `CF-Connecting-IP`, and
   the unsupported ones from section 5.4).
2. `REMOTE_ADDR` is private, loopback, CGNAT, unique-local or link-local.
3. Joomla's "Behind Load Balancer" is on (a strong signal; section 5.6).
4. `REMOTE_ADDR` is public and equals the last entry of the header: the web
   server already resolves the address (scenario C).
5. Since the update, most failed logins come from one private address, or a
   block exists for a private address or for `REMOTE_ADDR`.

The logic lives in the library as a pure function of `$_SERVER`, the
settings and Joomla's configuration (`ProxyDetector`), so a table of unit
tests can cover it.

### 5.2 What each scenario proposes

- **A:** confirm "no proxy". Optionally review the blocks made before the
  update.
- **B:** propose `useProxy=1`, trust the exact `REMOTE_ADDR`, and use the
  header actually present (prefer `Forwarded`, then `X-Forwarded-For`, then
  `CF-Connecting-IP`). Ask whether there is more than one proxy node and, if
  so, offer the narrowest common network.
- **C:** explain that the server already resolves the address and keep
  `useProxy=0`. Warn if `useProxy` is on.
- **D:** ask which provider. For Cloudflare, see section 5.3. Recommend the
  web server's real-IP module and restricting the origin to the CDN.
- **E:** show the unsupported-header warning (section 5.4). The site can't
  pass the proxy step until a supported header arrives, so it stays inactive.
  That is the correct outcome.

**Dry-run preview before saving.** Run `IpHelper::clientAddressFromHeader()`
with the proposed settings and ask "Is `x.x.x.x` your computer's address?",
reusing `HtmlView::addressCheck()`. This also catches a corporate proxy on
the admin's side that adds `X-Forwarded-For`.

**Confirming** saves the settings and the **fingerprint** of the confirmed
setup: the scenario, the header, and whether the request came from a
trusted proxy.

### 5.3 Headers: `CF-Connecting-IP` added

`CF-Connecting-IP` is added to the headers BFStop can use. Cloudflare is on
about 25% of all websites. It sets this header on every request it forwards,
overwriting any value the visitor sent, and it always holds exactly one
address.

- **Parsing:** the value counts only if it is exactly one valid address and
  `REMOTE_ADDR` is a trusted proxy.
- **Trusted proxies:** the step offers to fetch Cloudflare's published
  ranges (`https://www.cloudflare.com/ips-v4` and `ips-v6`). The fetch
  happens only when the admin clicks, and it goes to cloudflare.com only.
  All ranges fit the /8 and /16 limits.
- **Warning shown with it:** trusting all of Cloudflare lets anyone who uses
  Cloudflare reach the origin with an address of their choice (a Worker in
  the attacker's own zone can set it). This is safe only if the origin
  accepts Cloudflare traffic for this zone alone: Authenticated Origin Pulls
  with a per-zone certificate, Cloudflare Tunnel, or a firewall rule.
  Otherwise recommend the server's real-IP module (scenario C).

### 5.4 Headers BFStop doesn't use

These headers are recognised but not usable. They are listed in one constant,
`IpHelper::UnsupportedProxyHeaders`:

`X-Real-IP`, `True-Client-IP`, `Fastly-Client-IP`, `X-Client-IP`,
`X-Azure-ClientIP`, `X-Azure-SocketIP`, `X-Envoy-External-Address`,
`CloudFront-Viewer-Address`, `Fly-Client-IP`

When one of them is present:

- The step warns: "Your proxy sends `<header>`, which BFStop can't use."
- If a supported header is present too, it offers that one.
- Otherwise it shows the fix: `proxy_set_header X-Forwarded-For
  $proxy_add_x_forwarded_for;` on the proxy, or the web server's real-IP
  module.
- A **"Tell us about your setup"** link opens a pre-filled new issue at
  `https://github.com/codeling/bfstop/issues/new`. It contains only the
  header names, the detected scenario and the BFStop and Joomla versions:
  no header values, addresses or site URL. The admin opens the link; the
  site sends nothing.

Why these are not added:

- **`X-Real-IP`** is not more secure than `X-Forwarded-For` as BFStop reads
  it. With a single proxy that sets it, it holds the same address BFStop
  already takes from the proxy's `X-Forwarded-For` entry. With a proxy that
  doesn't set it, nginx passes the visitor's value through, so it is
  forgeable like `Client-Ip`. In a chain of proxies, each hop overwrites it
  with the hop before. The only benefit would be setups that set `X-Real-IP`
  but no `X-Forwarded-For`. Traefik, nginx-proxy and Plesk set both, and the
  usual nginx examples do too, so that group is small and can't be measured.
- **`Fastly-Client-IP`** is forgeable by default, according to Fastly's own
  documentation, unless the site's VCL overwrites it. Fastly appends to
  `X-Forwarded-For`, which BFStop can already use.
- **`True-Client-IP`** is opt-in at Akamai (about 0.7% of all websites) and
  at Cloudflare Enterprise (whose sites also get `CF-Connecting-IP`), so it
  is in use on well under 0.5% of websites.

### 5.5 The reminder

Shown in the proxy step, in the summary, in the success message after
activation, and in the help text of the settings page's proxy section:

> Keep these settings up to date. Whenever your hosting changes (a new proxy
> or CDN, load balancer nodes added or replaced, a move to another host),
> run the proxy check again. Wrong settings can block every visitor, or let
> attackers choose the address they are counted under.

### 5.6 Joomla's "Behind Load Balancer"

Joomla's Global Configuration has "Behind Load Balancer"
(`$behind_loadbalancer`). It makes Joomla's own `IpHelper` take the visitor
address from `X-Forwarded-For` or `Client-Ip`. It has no trusted-proxy list,
so it accepts the header from anyone, and Joomla issue #34365 reports that it
takes the wrong end of a proxy chain. BFStop doesn't use Joomla's
`IpHelper`; the only overlap is the User Actions Log, where BFStop's entries
(written through `ActionlogModel`) record Joomla's version of the address.

How the plan uses it:

- as a detection signal (section 5.1)
- as the criterion for disabling the plugin during a command-line upgrade
  (section 2)
- **never** as a source of BFStop's trust: there is no automatic `useProxy`,
  because Joomla's setting names no proxy address
- **never** by writing `configuration.php`

**Consistency hint** in the proxy step and the summary. It is information
only and doesn't hold back activation:

| BFStop | Joomla's setting | Effect | Hint |
|---|---|---|---|
| Proxy configured | Off | Joomla's sessions, User Actions Log (including BFStop's own entries) and privacy tools record the proxy's address | Switch it on, but only if the site can't be reached except through the proxy, because Joomla trusts the header from anyone |
| No proxy (A) | On | Any visitor can forge the address in Joomla's own logs. BFStop is unaffected. | Switch it off |
| Server already resolves the address (C) | On | Joomla reads the header, which may hold a forged entry | Switch it off |

## 6. Mismatch check

A shared library class, `ProxyMismatch`, compares the admin's own request
with the saved settings. It looks only at `$_SERVER`, the settings Joomla
already holds, and the dismissed mismatches in the `setup` state (one query,
backend only). It runs for users with `core.admin` on com_bfstop, in two
places with the same result:

- **the quick icon** on the Home Dashboard (section 8)
- **a banner on every BFStop backend view**, including the settings page's
  proxy section next to the existing address check

| Saved settings | What the admin's request shows | Message |
|---|---|---|
| No proxy | A forwarding header from a private address, or `CF-Connecting-IP` | "Your site now seems to be behind a proxy, load balancer or CDN" |
| Proxy configured | A header, but the address isn't a trusted proxy | "New or changed proxy address?" |
| Proxy configured | No header, and the address isn't trusted | "Proxy removed, or are you reaching the site directly?" |
| Proxy configured | A trusted proxy, but the configured header is missing and another known one is present | "Your proxy now sends a different header" |
| Proxy configured | The address is public and equals the header's last entry | "Your web server already resolves the visitor address; BFStop's proxy setting is no longer needed" |
| Any | Only unsupported headers present | The unsupported-header warning with the issue link |
| Any | Joomla's "Behind Load Balancer" doesn't match | The consistency hint (information only) |

Each message links to the proxy step alone. **"This is expected"** dismisses
that particular mismatch (stored by its fingerprint) everywhere: in the
banner, the quick icon and the assistant. A different mismatch shows again.
This covers admins who reach the backend another way (VPN, internal network,
corporate proxy).

There is no other change detection: no sampling of visitor requests and no
change mails.

## 7. Proxy warning in the block mail

When a block is created, the request that triggered it is checked:

- a private address with a forwarding header, or
- an address used for successful logins by at least two different accounts
  (known-address table)

If either is true, the existing block mail adds: "BFStop just blocked X,
which may be a proxy. If so, everyone behind it is blocked", with the
recovery steps (the backend block list, or `bfstop:unblock`).

**Recipients of the block mail with this warning:** BFStop's notification
recipients (addresses, user, group) plus the super users with "Receive
System Emails" switched on, or all active super users if none has it. Nobody
gets it twice: the addresses go through `NotifierHelper::validAddresses()`,
which already removes duplicates ignoring case. One mail per event per
person. Sending stays limited by the existing "Notify on blocks"
(`notifyBlockedNumber`) setting.

## 8. Quick icon

A new plugin, `plg_quickicon_bfstop`, installed and enabled by the package.
It adds a tile to the Home Dashboard's notification area (the context
Joomla's own status tiles use: `update_quickicon`, confirmed against Joomla
5.4.10 and 6.2.0 - the default of their quick icon plugins and of the
"Notifications" module of the installation). It is shown to users with
`core.manage` on com_bfstop; the states other than "fine" need `core.admin`.

| State (highest priority first) | Tile | Link |
|---|---|---|
| System plugin missing or disabled | **Error**: "Brute Force Stop is not active" | Assistant |
| Setup not completed (the plugin runs) | **Error**: "Brute Force Stop: complete the setup" | Assistant |
| A mismatch that hasn't been dismissed (section 6) | **Warning**: "Brute Force Stop: check proxy settings" | Assistant, proxy step only |
| Everything fine | Normal: "Brute Force Stop" | Component |

Cost: one query, and only when a dashboard is shown.

## 9. Console commands

For command-line installs and updates, automation and lockout recovery.
They are registered the way the Joomla console loads extension commands: a
console plugin, `plg_console_bfstop`. Joomla's `ConsoleApplication` imports
the plugins of the group "console" before it runs (5.4 and 6), and the
plugin adds its commands on `ApplicationEvents::BEFORE_EXECUTE`. The system
plugin can't: it is disabled until the setup is done.

- `bfstop:status`: setup state, plugin enabled, proxy settings
- `bfstop:setup --no-proxy | --trusted=<list> --header=<header>`: runs the
  required steps and activates protection
- `bfstop:unblock <address>`: lifts the blocks of an address, including its
  `.htaccess` and nginx entries

A documented SQL fallback covers sites where the console can't be used.

## 10. Implementation outline

- **library**
  - `Service/Setup/SetupState`: the `setup` row of `#__bfstop_state`
  - `Service/Setup/ProxyDetector`: signals, scenario, proposal, fingerprint
  - `Service/Setup/ProxyMismatch`: the mismatch check and dismissals
  - `Service/Setup/SettingsAudit`: stored values that block saving (through
    the settings form), and the changes of meaning
  - `Helper/IpHelper`: `CF-Connecting-IP` (single value), and
    `UnsupportedProxyHeaders`
  - `Helper/NotifierHelper`: super users among the recipients, the proxy
    warning in the block mail
- **plugin**
  - `updatescript.php`: no auto-enable in `install()`; in `update()`,
    detection, the `behind_loadbalancer` check, disabling, and writing the
    `setup` state; the new messages in `postflight()`
  - the block decision passes the "looks like a proxy" information to the
    block mail
- **component**
  - `Controller/SetupController`, `Model/SetupModel` (saves through
    `SettingsModel`), `View/Setup` and templates per step
  - banners in the views; settings page buttons; "Re-run proxy check"
  - the post-installation message (component manifest and install script)
  - action log events: step applied, protection activated
- **new extensions in the package:** `plg_quickicon_bfstop`, and
  `plg_console_bfstop` if a console plugin is how the commands are registered
- **language:** keys in all languages (the language check in CI fails
  otherwise)
- **README:** "After installing, run the setup assistant in Components →
  Brute Force Stop; it activates the plugin."

## 11. Tests

- **Unit:**
  - `ProxyDetector`: a table covering scenarios A–E, including
    `CF-Connecting-IP` only, unsupported headers only, a corporate proxy on
    the admin's side, and `behind_loadbalancer`
  - `ProxyMismatch`: every row of the table in section 6, and dismissal by
    fingerprint
  - `IpHelper`: `CF-Connecting-IP` parsing (a single valid address only;
    lists, ports and garbage rejected; only from a trusted proxy)
  - `SettingsAudit`: 1.5.2 settings fixtures with each blocking value
- **Integration:**
  - `InstallTest`: the plugin is **disabled** after install, and enabled
    after `bfstop:setup` or the assistant's activation
  - applying each step through `SetupModel`
  - the dry-run preview
  - the block mail's proxy warning and recipient deduplication
  - the quick icon states
  - the query counts stay the same for frontend requests
- **Upgrade** (`tests/Upgrade`, fixtures):
  - browser upgrade with an `X-Forwarded-For` snapshot from a private
    address: plugin disabled, `setup` state written
  - without proxy signals: plugin stays enabled
  - command-line upgrade with `behind_loadbalancer`: disabled
  - "Reporting Only" with a delay: step 2 flags it
- **CI:** the install scripts call `bfstop:setup --no-proxy` instead of
  relying on the auto-enable.

## 12. Phases

1. **Ships with 2.0.0:**
   - activation model: no auto-enable on install; disabling during the
     upgrade for B, D or E
   - quick icon with all three states
   - the shared `ProxyMismatch` check, shown in the quick icon and in the
     BFStop backend
   - the proxy step, with the reminder, `CF-Connecting-IP`, the
     unsupported-header warnings and the Joomla consistency hint
   - the inline panel for values that block saving
   - the blocking-mode step, including "Reporting Only with a delay"
   - console commands
   - the proxy warning in the block mail, with super users among the
     recipients
2. **Next:** rate-limiting guidance, the notifications steps (3, 3b),
   protected parts (4), the clean-up after the proxy fix (1b), and the
   legacy `.htaccess` step (2b).
3. **Later:** privacy and username hashing (5), the scheduler review (7), and
   the full summary.

## 13. Decisions taken while planning

| Topic | Decision | Reason |
|---|---|---|
| Fresh installs | The assistant runs on fresh installs too | Proxy configuration matters from the first request |
| Auto-enable on install | Removed; the assistant activates the plugin | Never released; the plugin should only run once its address handling is known to be right |
| Lockout guard mode | **Rejected** | Disabling the plugin until the assistant is done does the job without a separate mode that later development would have to keep in mind. A guard re-engaged by detected changes could also be triggered by forged headers (nginx real-IP recursion). |
| Pre-upgrade readiness check (a 1.5.3 release) | **Rejected** | It would be the assistant run earlier. The installer already refuses wrong PHP and Joomla versions, and disabling during the upgrade covers the gap. |
| Sampling visitor requests and traffic-share thresholds for change detection | **Rejected** | Too elaborate for the purpose. Replaced by the reminder and the mismatch check on the admin's own requests (quick icon and BFStop backend). |
| Change mails | **Rejected**, except the proxy warning in the block mail | The block-mail warning needs no detection machinery and covers the dangerous moment |
| `CF-Connecting-IP` | **Added** | About 25% of all websites; overwritten by Cloudflare; a single value |
| `X-Real-IP`, `Fastly-Client-IP`, `True-Client-IP` | **Not added**; detected and warned about, with an issue link | See section 5.4 |
| Hashing old usernames | **Opt-in** step in the assistant | It changes stored data; the admin decides |
| Writing `configuration.php` (`$live_site`, `behind_loadbalancer`) | **Never** | Touching Joomla's core configuration is not the extension's job; the assistant shows the line to add |
| Built-in CDN address ranges | **Not shipped**; Cloudflare's are fetched on request | Ranges change; trusting them needs the origin restriction the step explains |

## 14. Implementation notes (phase 1)

Where the implementation differs from the plan above, or settles what the
plan left open:

- **State:** a row of `#__bfstop_state` holds 255 characters, so the state
  is three rows: `setup` (mode, version updated from, why the update
  disabled the plugin, scenario and header names of the update's request,
  delays removed, `.htaccess` not rewritten, the confirmed fingerprint,
  `completed`), `setupSteps` (the steps which aren't pending) and
  `setupDismissed` (up to 16 fingerprints). They are read with one query.
  The installer script writes `setup` itself, in the same form (a test
  checks that `SetupState` reads it). An installation stays in mode
  `install` across updates until its setup is completed; any update whose
  setup isn't completed records its findings and may disable the plugin.
- **Detection in the installer:** the update can't use the library's
  classes (those of the version replaced may be loaded), so it has its own
  copy of the scenario detection and of the header and network lists; a
  test checks that it agrees with `ProxyDetector` on the table of
  scenarios. Scenario C needs a public `REMOTE_ADDR`, as in 5.1.
- **Pure functions:** `ProxyDetector` and `ProxyMismatch` take the proxy
  settings as an array (`ProxyDetector::proxySettings()` makes it from the
  settings), so that their unit tests need no Joomla.
- **`SettingsAudit`** validates each stored value with its field of the
  settings form, plus `SettingsModel::crossFieldErrors()` (the checks across
  fields, which `SettingsModel::validate()` uses too). Finding the values
  needs Joomla's form, so that part is tested in the integration test
  `SetupTest` (with settings of 1.5.2); the unit test covers the proposed
  fixes.
- **Mismatch fingerprints** hold the code, the names of the headers present
  and whether `REMOTE_ADDR` is public or not - no address, so a dynamic
  address doesn't bring a dismissed mismatch back.
- **Banners:** Joomla sanitises its messages (`Joomla.sanitizeHtml()` allows
  no `form`), so a banner can't carry a token-checked "This is expected"
  button. The banners link to the assistant's proxy step, where each
  mismatch has that button. Information-only hints (Joomla's "Behind Load
  Balancer") are shown as notices and don't make the quick icon a warning.
- **Post-installation message:** of type "action" (Joomla's `MessagesModel`
  drops the URL of a "link" message before it checks that there is one, in
  5.4 and 6), and written into `#__postinstall_messages` by the component's
  installer script directly, as the model would: from the command line the
  model finds no table class. The component's uninstallation removes it.
- **Dry run:** the confirmation carries the address the page showed, which
  the settings must still give when they are saved - settings changed after
  the check have to be checked again.
- **Console:** `bfstop:setup` replaces stored values which block saving
  only with `--fix` (it lists them otherwise), keeps "Reporting Only" only
  with `--block-mode=off`, and takes the proxy settings without a dry run
  (there is no request). The commands print English, as Joomla's own; the
  model's messages are translated. The console plugin uses the component's
  setup model (booted through Joomla), so the settings are checked as in
  the browser.
- **Block mail:** whether the blocked address may be a proxy is decided
  before the block, and only when a block mail may be sent; the check of
  the known-address table costs one query then. The query counts of page
  views, blocked requests and failed logins are unchanged.
- **Tests of the update:** the update suite (`tests/Upgrade`) runs one
  update from the command line, so it checks that the plugin stays enabled
  there and that the setup state is recorded. The browser update with an
  `X-Forwarded-For` request from a private address, and the command-line
  update with "Behind Load Balancer", are tested in `InstallerScriptTest`,
  which calls the installer script as Joomla does; "Reporting Only" with a
  delay in `SetupTest`.

## 15. Implementation notes (phases 2 and 3)

- **Pages:** the assistant shows the pages of the steps which apply: the
  clean-up after an update with a proxy configured, the `.htaccess` step
  while the file has the section of 1.x (or the update couldn't rewrite
  it), rate limiting where the update removed delays which were in use
  (for a new installation, the advice is in the summary), privacy after an
  update. Every optional step can be skipped; a saved step goes on to the
  next page.
- **Steps of settings** (notifications, protected parts, privacy) render
  the settings form's own fields and save only the settings of the step,
  through the settings model. The changed meaning of `notifyBlockedUser`
  (3b) is explained on the notifications page and decided with it.
- **Clean-up (1b)** works on the trusted proxies of the saved settings:
  active blocks whose entry lies in or contains a proxy are lifted, the
  failed logins, offences and known-address rows of such entries removed.
  There is no record of when the update ran, so it isn't limited to what
  happened since. The proxy step also lists active blocks of non-public
  addresses and of the request's own address (signal 5 of section 5.1,
  without the share of failed logins).
- **Hashing old usernames (5)** goes on in rounds of about five seconds,
  each a POST of the page, until done (no JavaScript). The log is cleared
  on BFStop's log page, which the step links to.
- **Scheduler (7)** shows the task plugin, the maintenance task and
  whether the Task Scheduler's lazy mode is on, with links.

