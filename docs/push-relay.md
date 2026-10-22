# Push relay

Apple delivers pushes to the kōan iOS app only when they are signed with a key belonging to the developer's team, so a self-hosted kōan server cannot wake a suspended iPhone or ask it to play on its own. The push relay at `push.koan.rocks` holds a topic-specific key of its own and forwards pushes for any server.

The key belongs to the developer's Apple account, which answers to Apple for every push sent under it, so the relay is built to bound what anyone can cause through it. The worst a hostile server can do is make a phone show kōan's own text, within small quotas, to people who chose to sign in to it, and put words of its own, bounded, on a Live Activity one of those people started. Nobody can make the relay send Apple a flood, a stream of errors, or anything a server wrote beyond those bounded fields.

That bound holds only together with the app: its notification service extension shows nothing a server wrote, only its own template (see [What a phone shows](#what-a-phone-shows)).

A registration on the production gateway needs an [App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity) assertion: Apple's word that it comes from kōan's app on a real device. Nothing reaches Apple for a production registration without one, so made-up tokens there are bounded by who can ask as well as by rate. The sandbox gateway, for development builds, takes an assertion when given and does without one, since development builds also run where App Attest does not (the simulator); see [App Attest](#app-attest).

The relay is `crates/koan-push-relay` in this repository. This page specifies its API; running it is under [Operating the relay](#operating-the-relay).

## Parties

- **The app** holds its APNs device token. It registers the token with the relay once for each server it uses, gives each server the handle it gets back, and keeps the revoker for itself. It gives its raw tokens, the device's and its Live Activities', to no server: a server that held an activity's token could register it under a revoker of its own, outside the device's revocation and quotas.
- **A server** holds the handles its users' apps gave it, and asks the relay to push to them.
- **The relay** opens handles, applies quotas and writes everything Apple is sent, apart from an encrypted blob a server may attach to a notification and the fields of a Live Activity's state, which it bounds.

## Handles

A handle is the device token, the gateway (production or sandbox), the time it was minted and a slot, sealed with AES-256-GCM-SIV under a key only the relay holds, and encoded as base64url without padding:

```text
version (1) | key id (1) | nonce (12) | sealed( flags (1) | minted ms (8, big-endian) | slot (16) | token ) | tag (16)
```

The version and key id are authenticated with the rest. A handle is opaque to everyone but the relay: clients store it and send it back unchanged, and must not parse it. It is at most 228 characters.

The **slot** is sixteen random bytes the app chooses for one server and keeps for it, across renewals, for as long as it uses that server. The relay counts that server's allowance for the device by it, so a renewed handle shares the old one's allowance, and stamps it on every notification it sends (`koan-from`), so the app knows which server a notification came through without taking any server's word for it.

A handle opens for 60 days from minting by default, and at most 365 (`expires` in the registration response). The app registers again at half its lifetime and gives the server the new handle on its next link. A handle minted more than a lifetime ahead of the relay's clock is answered `503`, not `410`: the clock is wrong, not the handle.

Registration also returns a **revoker**: the same sealed form with a flag set, kept by the app and given to no server. A revoker cannot be pushed through, and revoking takes one, so a server, which holds handles alone, cannot revoke a device.

The relay keeps no record of handles. It can rotate its sealing key: handles sealed under a key it still lists keep opening, and a key is retired once every handle sealed under it has expired.

## Revocation

A device revokes by sending a revoker from any of its registrations that has not expired. Revoking asks nothing of Apple: the relay minted the revoker only for a token Apple had accepted. Every handle for that token, and every revoker, minted at or before that moment stops opening, and so does any minted in the ten minutes after it, so that a clock stepped back by up to that much cannot bring a revoked handle back. A registration after a revocation is minted past that window. If the relay's clock has read later than it does now, the revocation is recorded at that later time instead, so a handle minted while the clock ran fast cannot outrun it; and a device's revocation is always recorded after its previous one, so it reaches a handle minted past that one's window.

The app revokes when it signs out of a server, then registers again, gives each server it still uses a fresh handle, and keeps the fresh revoker. It waits for the revocation's `204` before registering again, and registers again after any revocation that succeeds, including a retried one: a revocation retires every handle minted before it reached the relay, whichever request asked for them. A retried revocation answered `410` means the first one landed and retired the revoker with the rest; the app treats it as done and registers again.

When Apple answers a push that the app is no longer on the device (`410`), or refuses a token it accepted at registration as no longer valid (`400 BadDeviceToken` or `DeviceTokenNotForTopic`), the relay records a revocation for that device itself, so a server that ignores the `410` cannot keep sending to it. Pushes to the device already on their way when the first answer comes add nothing, and further pushes stop at the relay.

The relay stores one row per revoking or gone device: a keyed hash of the token and the time. A row is kept for 365 days, the longest a handle can be configured to open, measured from the newest row rather than the clock if the clock reads later, so neither a change of lifetime nor a clock jumped ahead lets a revoked handle open again.

## Proof of a device

Before minting a device's handle, the relay sends the token a background push (`wake-now`) and goes on only if Apple accepts it, so no device handle can be had for a made-up token. The app is open when it registers, so the wake asks nothing of it.

A made-up token reaches Apple in two places: a registration's proof, and an update to a Live Activity, whose token cannot be proven without showing on the lock screen. Proofs have limits of their own:

- a rate for everyone;
- a count, per caller address, of tokens Apple refused: past its limit, that address proves nothing until the count falls back;
- the same count across everyone, past which no registration is proved until it falls back.

Room in both counts is taken before a proof is sent and handed back if Apple accepts the token, so racing proofs cannot overrun them. A proof also counts against the device's wakes. Revocation asks nothing of Apple, so none of this can stop a device revoking. A proof Apple refuses for a reason the relay does not know is answered `503` and counted in neither, since the token was not shown to be made up.

A Live Activity's update takes the same room in everyone's count, and in a count of its device's activity tokens Apple refused, since only that device's revoker could have registered it: one installation can make the relay send Apple no more made-up tokens than that count allows.

## App Attest

The app makes a key in the Secure Enclave (`DCAppAttestService.generateKey`), asks the relay for a challenge, has Apple attest the key over the challenge (`attestKey`, with the SHA-256 of the challenge string exactly as the relay sent it, its UTF-8 bytes, not decoded), and sends the attestation to `/v1/attest`. The relay checks it as Apple describes: the certificate chain to Apple's App Attestation root, the nonce in the credential certificate against the authenticator data and the challenge, the key's id, the app id (team id and bundle id) in the relying party hash, a counter of zero, and the environment, production or development. It answers with the key sealed as handles are, which the app keeps until it expires and then attests a new key.

Each registration then carries an assertion (`generateAssertion`) over the SHA-256 of this, for a fresh challenge:

```text
"koan-relay register 1" | 0x00 | challenge (as sent) | 0x00 | device token | slot (16) | sandbox (1 byte, 0 or 1)
```

so an assertion registers exactly the token, slot and gateway it was made for. A development key registers only on the sandbox gateway.

The relay keeps no state for any of this. A challenge is the time it was issued, random bytes and an HMAC over both, good for five minutes; the attested key is sealed. The assertion's counter is not tracked: an assertion is bound to a challenge that lapses in minutes and to the registration it signs, so replaying one only repeats that registration.

## Endpoints

All requests are `POST` with a JSON body of at most 8 KiB, and `Content-Type: application/json`; anything else is refused with `415` before it is read. That keeps a web page from making visitors' browsers call the relay: a cross-origin JSON request needs a CORS preflight, which the relay never answers. Unknown fields are refused with `400`, unlike the link protocol: the relay accepts nothing it does not write itself. A body that takes longer than five seconds to arrive is answered `408`, and one too large `413`. Errors have the body `{"error": "<reason>"}`; the reason is for logs, and clients act on the status alone.

### `POST /v1/challenge`

Called by the app, with `{}`. The answer is `200` with `{ "challenge": "<base64url>", "expires": <unix seconds> }`.

### `POST /v1/attest`

Called by the app.

```json
{ "key_id": "<base64url>", "attestation": "<base64url>", "challenge": "<challenge>" }
```

The answer is `200` with `{ "key": "<attested key>", "production": true, "expires": <unix seconds> }`. `400` means the attestation does not check out, or the challenge has lapsed or was not this relay's.

### `POST /v1/register`

Called by the app.

```json
{ "token": "<device token, hex>", "sandbox": false, "slot": "<16 bytes, hex>", "attest": { "key": "<attested key>", "challenge": "<challenge>", "assertion": "<base64url>" } }
```

`sandbox` is true for development builds, whose tokens only Apple's sandbox gateway accepts; it may be absent. `attest` is required on the production gateway, and optional on sandbox; `400` names what is wrong with it. The answer is `200`:

```json
{ "handle": "<handle>", "expires": 1767225600 }
```

`expires` is in Unix seconds. `400` means the token is not 8 to 100 bytes of hex, the slot is not 16 bytes of hex, the relay holds no key for the requested gateway, or Apple refused the token; `429` and `503` are as for a push.

The answer also carries `"revoker": "<revoker>"`, for the app alone.

### `POST /v1/revoke`

Called by the app.

```json
{ "revoker": "<revoker>" }
```

The answer is `204` once the revocation is on disk. `400` means what was sent is a handle, not a revoker; `410` that the revoker does not open (unknown, altered, expired, or already revoked); `429` and `503` are as for a push.

### `POST /v1/register-activity`

Called by the app, for a Live Activity it has started, with the activity's push token.

```json
{ "revoker": "<revoker>", "token": "<activity token, hex>", "slot": "<16 bytes, hex>" }
```

The answer is `200` with `{ "handle": "<handle>", "expires": <unix seconds> }`, a handle the app gives the server whose slot it names, to push the activity's updates through. Only the app holds a revoker, so only the app can register an activity. The relay sends no proof: an activity's token takes only Live Activity pushes, and one would show on the lock screen.

The handle seals the activity's token with its device's token hash, so the device's revocation retires it, the device's quotas count it, and it is for the revoker's gateway. `400` means what was sent is a handle, not a revoker, or the token or slot is malformed; `410` that the revoker does not open or the relay no longer serves its gateway.

### `POST /v1/push`

Called by servers. There is no other authentication: the handle is the capability, and quotas bound what holding one is worth.

```json
{ "handle": "<handle>", "kind": "notify", "blob": "<base64url>" }
```

or, through an activity's handle:

```json
{ "handle": "<handle>", "kind": "activity", "state": { "device": "Desk", "linked": true, "title": "…", "artist": "…", "album": "…", "playing": true, "positionMs": 0, "durationMs": 0, "at": 1767225600.5, "art": "<base64 JPEG>" } }
```

| `kind` | Apple push | What the phone gets |
|--------|------------|---------------------|
| `wake` | background, low priority, collapse id `koan-wake`, expires in an hour | `content-available` and nothing else: the app wakes, links and takes what waits for it |
| `wake-now` | as `wake`, collapse id `koan-wake-now`, expires in a minute | the same, for a wake that is no use late |
| `summon` | alert, collapse id `koan-summon-<slot>`, expires in two minutes | the relay's notification |
| `notify` | alert, collapse id `koan-play-<slot>`, expires in ten minutes | the relay's notification |
| `activity` | Live Activity update, to the topic with `.push-type.liveactivity`, expires in a minute | the activity, drawn from `state` by the app's widget |

A notification's collapse id carries its server's slot, so one server's notification replaces only that server's last one.

The relay's notification is titled "kōan", reads "Something is waiting to play. Tap to open.", plays the default sound and has the interruption level `active`: never `time-sensitive`, since the relay cannot vouch for the server, so it does not break through a Focus. It carries the slot as `koan-from`. A `summon` or `notify` may carry `blob`, at most 3072 base64url characters, which the relay passes to the app under `koan-e2e` with `mutable-content` set. A `wake` or `wake-now` with a blob is refused with `400`. The relay does not read the blob.

An `activity` goes only through an activity's handle, and only it does; it carries `state` and nothing else does. iOS draws a Live Activity's state in the app's widget without passing it through the app, so it cannot be encrypted, and the relay bounds it instead:

- `state` has the fields the widget's `ContentState` has; a field the relay does not know is dropped and never sent, and `title`, `artist`, `album` and `art` are left out of what Apple is sent when absent;
- `device` is cut to 48 bytes and `title`, `artist` and `album` to 256, at a character, with control and formatting characters (those that reorder or hide text among them) removed and whitespace made single spaces;
- `art` must be base64 of a JPEG, at most 2600 characters, or the update is refused with `400`;
- `durationMs` is at most a day and `positionMs` at most `durationMs`;
- `at`, when the position was true, is the relay's time if the server's is over an hour behind it or a minute ahead;
- the update's `timestamp` is `at`, and its `stale-date`, when the lock screen dims it, eight hours from the relay's clock.

Apple answering that an activity's token is gone means the activity has ended: the push is answered `410`, the device is left as it was, and later updates through that handle stop at the relay. An activity token Apple does not know is treated the same way, and stays counted against its device.

| Status | Meaning | What the server does |
|--------|---------|----------------------|
| `204` | Apple accepted the push | |
| `400` | The request is malformed | Fix the request |
| `410` | The handle does not open (unknown, altered, expired, revoked), the relay no longer serves its gateway, or Apple says the app is gone from the device | Forget the handle; the app sends a new one when it next links |
| `429` | A quota is spent, or Apple is throttling the device | Wait at least `Retry-After` seconds |
| `503` | The relay or Apple cannot take the push now, Apple refused it for a reason the relay does not know, or the relay has stopped sending because Apple refuses it (`Retry-After` is then minutes) | Retry after `Retry-After` seconds |

A push whose sender hangs up once it has been accepted for sending still goes to Apple, and is counted as sent.

### What a phone shows

The extension decrypts the blob, but decrypting proves only that the sender holds the device's public key, which every server the person signed in to does. So the extension shows nothing a server wrote:

- It names the server from `koan-from`, the slot the relay stamped, mapped to the server the app gave that slot, never from anything in the blob. Cover art is fetched only from that server's own origin, must be an image, and is capped in size.
- The blob carries structured fields, never display text: the command, and the title and artist of what it would play. The extension fills its own template with them, capped in length and stripped of links, phone numbers, addresses and control characters. A title or body in the blob is ignored.
- Tapping runs only playback commands.
- When the blob does not decrypt, or `koan-from` names no server the app knows, the relay's text stands and tapping opens the app.

A Live Activity shows the state the relay bounded, through the widget's own layout. The words in it are a server's, within those bounds: a server the person signed in to can name a track what it likes on their lock screen, as it can in its library.

## Quotas

Each relay process counts:

| Counted per | Default |
|-------------|---------|
| Server's handle: notifications | 6 an hour |
| Server's handle: wakes | 12 an hour |
| Device, across its servers: notifications | 20 an hour |
| Device, across its servers: wakes, proofs of registration included | 30 an hour |
| Device: revocations | 10 an hour |
| Server's handle: Live Activity updates | 120 an hour |
| Device, across its servers: Live Activity updates | 240 an hour |
| Device: Live Activity tokens Apple refuses as unknown | 10 an hour |
| Attested key: registrations | 30 an hour |
| Caller address: challenges and attestations | 120 a minute |
| Caller address: pushes | 6000 a minute |
| Caller address: registrations | 120 a minute |
| Caller address: revocations | 60 a minute |
| Caller address: tokens Apple refuses in proofs | 10 an hour |
| Everyone: tokens Apple refuses in proofs, before registrations are held | 360 an hour |
| Everyone: proofs sent to Apple | 20 a second |
| Everyone: pushes sent to Apple | 20,000 a second |

A server's handle is counted by device and slot, so its renewals share it. A device is counted by its token, so its ceiling holds whichever servers hold its handles. A caller address is counted by its IPv4 address, or its IPv6 /64 for pushes and /48 for registrations, revocations and refused tokens: the larger block one site is commonly given, so a site cannot spread made-up tokens over its addresses, at the price that neighbours in a /48 share those allowances. Each count allows its whole allowance as a burst and then refills evenly over the period. A push the relay or Apple could not take is not counted against its server or device; one that reached Apple stays counted against the relay's own rates towards Apple, whatever Apple answered.

Behind proxies, the address is read from the header the relay is configured to trust (`client_ip_header`), across all its lines, `client_ip_hops` addresses back from the end. A request without a readable address there is refused with `400`, rather than counted as the proxy's own address, where every such caller would share one allowance. The relay must be reachable only through the proxy that writes that header, since anyone reaching it directly can write it themselves.

## When Apple refuses the relay

When Apple refuses a gateway's credential (an invalid, missing or over-refreshed signing key, a wrong key id, topic or environment, an expired signing key signed only moments ago, which means the relay's clock is wrong, or tokens proven at registration refused for five different devices on that gateway within ten minutes, counted as a window rather than a rate), every push through that gateway would be refused the same way, and sending on with a credential Apple has refused is what gets a key looked at. That gateway stops: its pushes and proofs are answered `503` with `Retry-After: 300` without reaching Apple, and one a minute is let through to learn whether it has been fixed: a push to a proven device token, since an answer about any other token says nothing about the relay. A device whose token is refused once the relay has concluded that it is itself misconfigured is not retired: its server is answered `503`. It opens again only when Apple answers in a way only a working credential gets; the other gateway carries on meanwhile. An answer the relay does not recognise is refused with `503` and `Retry-After: 300` but does not stop the gateway. The relay never signs a new provider token within twenty minutes of the last.

## What the relay sees and keeps

It sees, per request: a device token or a Live Activity's (registration only), a handle or revoker, which it opens to a token in memory, the kind of push, an encrypted blob it cannot read, a Live Activity's state, and the caller's address.

It keeps:

- the revocation table: a keyed hash of each revoking or gone device's token and when, for 365 days, and the latest time its clock has read;
- counters for quotas, in memory: keyed hashes of tokens, slots, and caller addresses as they are (IPv6 cut to its prefix), each forgotten once its allowance has refilled;
- aggregate counts by route and outcome, pushes and proofs.

It writes no request log, and nothing it writes to disk or to its own log names a token, a handle, a caller or a server. Its own log level is `KOAN_RELAY_LOG` (`info` by default); every library it uses logs at `warn` whatever `RUST_LOG` says, since at `debug` the HTTP libraries log request URLs, and Apple's hold device tokens.

## Operating the relay

`koan-push-relay` reads a TOML file named by `KOAN_RELAY_CONFIG`, overridden by environment variables named `KOAN_RELAY__` and the key path with `__` between levels (`KOAN_RELAY__APNS__PRODUCTION__KEY`). The double underscore after the prefix keeps variables Kubernetes injects for a Service named `koan-relay` out of the configuration; turning off `enableServiceLinks` for the relay's pod avoids them altogether. It refuses to start without a token key, a current handle key and at least one APNs key that can sign, or with a limit of zero.

```toml
listen = "0.0.0.0:8080"
# Prometheus metrics and /healthz, for the cluster only.
metrics_listen = "0.0.0.0:9090"
# Only behind a proxy that sets this header itself. Traefik overwrites
# x-real-ip with the address it saw on every request from a source it does
# not trust, so it holds the caller alone.
client_ip_header = "x-real-ip"
# Which address in that header, counting back from the end, is the caller:
# 1 for a header holding only the caller, or one proxy appending what it saw
# to x-forwarded-for; 2 behind two proxies that each append.
client_ip_hops = 1
store = "/data/relay.db"
topic = "cc.blit.koan"
# 32 random bytes, base64. Never rotated: revocations are found by it.
token_key = "…"

[handles]
current = 1
# At most 365.
lifetime_days = 60
# 32 random bytes each, base64. Add a key and make it current to rotate;
# remove the old one once lifetime_days have passed.
keys = { "1" = "…" }

[apns]
team_id = "…"
# HTTP/2 connections kept to each gateway, 1 to 64.
connections = 4
# Pushes waiting on Apple at once; beyond it, 503.
max_in_flight = 4096

# Topic-specific keys, scoped to cc.blit.koan, one per gateway.
[apns.production]
key_id = "…"
key_path = "/secrets/production.p8"

[apns.sandbox]
key_id = "…"
key_path = "/secrets/sandbox.p8"

[attestation]
# Whether a production registration needs an App Attest assertion.
required = true
# A root to check App Attest certificates against in place of Apple's, PEM.
# For tests only: whoever holds its key can attest anything.
# root = "-----BEGIN CERTIFICATE-----..."

[limits]
handle_alerts_per_hour = 6
handle_wakes_per_hour = 12
device_alerts_per_hour = 20
device_wakes_per_hour = 30
device_revocations_per_hour = 10
handle_activity_per_hour = 120
device_activity_per_hour = 240
device_bad_activity_tokens_per_hour = 10
ip_attestations_per_minute = 120
attested_key_registrations_per_hour = 30
ip_pushes_per_minute = 6000
ip_registrations_per_minute = 120
ip_revocations_per_minute = 60
ip_bad_tokens_per_hour = 10
bad_tokens_per_hour = 360
proofs_per_second = 20
global_pushes_per_second = 20000
# Callers each limiter keeps a count for; past it, a caller it has no count
# for is refused with 503 until idle counts are swept.
max_tracked = 1000000
# Devices the revocation table holds; past it, new revocations get 503.
max_revocations = 1000000
# Requests being worked on at once; past it, 503.
max_requests = 50000
```

Every push is answered from memory, so Apple's round trip, carried over `connections` HTTP/2 connections per gateway, is what bounds throughput.

`/metrics` on the metrics listener counts requests by route and outcome, pushes sent by kind, proofs by Apple's answer, and shows each gateway's breaker (`koan_relay_production_held`, `koan_relay_sandbox_held`), which is worth an alert.

The revocation table is a SQLite file, so one process writes it. Replicas each keep their own quotas, which multiplies the allowances by the number of replicas, and would need a shared revocation table; until there is a need for more than one process, there is one.

### Deploying

Each release publishes the image `ghcr.io/radiosilence/koan-push-relay` and the Pulumi component `@radiosilence/koan-relay-pulumi` (`deploy/pulumi`) at the relay's version, so a pinned package deploys exactly that image. `createPushRelay` makes the Deployment, its Service and a NetworkPolicy; the deployer routes the hostname to the Service, and supplies a Secret holding the credentials (`token-key`, `handle-key-<id>`, and each gateway's `.p8`), so none of them appears in the Deployment.

```ts
import { createPushRelay } from "@radiosilence/koan-relay-pulumi";

createPushRelay(provider, "koan", "push.koan.rocks", {
  existingSecret: "koan-push-relay",
  apns: {
    teamId: "…",
    // A team key serves both gateways from one entry.
    production: { keyId: "…", secretKey: "apns-key" },
    sandbox: { keyId: "…", secretKey: "apns-key" },
  },
  store: { hostPath: "/var/lib/koan-push-relay" },
  nodeSelector: { "kubernetes.io/hostname": "…" },
  // Any of the quotas above, by their camelCase names.
  limits: { handleAlertsPerHour: 30 },
});
```

The component runs one replica and replaces it rather than rolling it, since a rollout would briefly run two writers. A `store.hostPath` needs the pod pinned to that node. Only the proxy may reach the relay's port, since the relay limits callers by the address that proxy writes: anything else reaching it could choose its own address. By default that is Traefik, by its pod label; `networkPolicy.from` names another.
