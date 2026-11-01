# Changelog

## 0.1.3

### Security

- Update tokio and other packages for security

### Changed

- **The Pulumi package installs with aube, and its init image is Alpine 3.24.** The package is built, tested and version-bumped with aube (`aube-lock.yaml` replaces `package-lock.json`); npm only publishes it. Its dependencies move to @pulumi/kubernetes 4.34, @pulumi/pulumi 3.273, zod 4.6 and vitest 5. `initPermissions.image` now defaults to `alpine:3.24`, so a deployment that does not set it pulls a new image for the store permissions init container on its next update.

### Fixed

- **`koan-relay-client` keeps a base URL's path, and the relay stops leaking stopped activities.** `Client::new("https://example.org/relay")` now sends to `/relay/v1/…`; without a trailing slash it used to send to `/v1/…` at the host's root. In the relay, ended Live Activities and gone devices it could not record are forgotten once their handles expire, where the sets used to fill and then let pushes to newly ended activities reach Apple again (`koan_relay_gone` and `koan_relay_ended_activities` report their sizes); a gone device's revocation no longer holds one of `apns.max_in_flight`'s places while it is written; behind a proxy, a forwarded-address line that is not text is refused rather than passed over, which let a caller move the count onto an address it wrote; and an SQLite error reading the revocation table at startup stops the relay rather than being read as zero.

### Internal

- **Workflows are linted.** CI runs actionlint, with shellcheck, over `.github/workflows`, and `just check` runs it locally.
- **Dependencies.** rusqlite 0.41 (bundled SQLite from libsqlite3-sys 0.39), parking_lot 0.13 and tokio 1.54.1, with the lockfile brought up to date.
- **The Pulumi package is linted and formatted with oxc.** oxlint and oxfmt run in its check and `just fmt`, and the pre-commit hook formats staged TypeScript. The schema tests now name the error each refusal should give.
- **Builds use the latest stable Rust.** `rust-version` is removed from the manifests, so dependency resolution targets the toolchain in use instead of holding crates back for an old compiler; mise installs `rust` at `latest`.

## 0.1.2

### Added

- **`koan-relay-client`.** The crate kōan's apps and servers call the relay through: registering devices and Live Activities, revoking, pushes and activity updates, with the relay's answers as errors to act on. It shares the relay's types and version, and is reached over https only. A Live Activity's absent fields are now left out of what Apple is sent, and a field the relay does not know is dropped rather than refused.
- **App Attest.** A registration on the production gateway needs an App Attest assertion, so nothing reaches Apple for it unless it comes from kōan's app on a real device. `/v1/challenge` and `/v1/attest` give the app a key the relay has verified against Apple's root; the client crate gains `challenge`, `attest`, `register_attested` and `client_data`. The relay stays stateless: challenges and keys are sealed, not stored.

## 0.1.1

### Fixed

- **Review of 0.1.0.** The Pulumi component gives the pod the group its key and store need, and names its Service `<prefix>-service` as its deployers route. Live Activity updates count tokens Apple refuses against their device and everyone's, an ended activity is not sent to again, and its 4 KB bound counts JSON escaping. A gone device is retired once, a device whose token is refused once the relay has blamed itself is not retired, five refusals are counted over a ten-minute window, only a push to a proven token may probe a held gateway, a request that reached Apple stays counted against the relay's own rates, and an answer Apple's table does not list is refused as unavailable rather than counted. `BadEnvironmentKeyInToken`, Apple's spelling on the wire, and the 403 certificate answers now stop a gateway. Text keeps zero-width joiners and loses every other format character.

## 0.1.0

### Added

- **Push relay.** Forwards pushes to Apple for kōan servers that do not hold the developer's key. Servers hold sealed handles instead of device tokens, and the relay writes the whole of what Apple is sent, within quotas built around Apple's rules for the developer's account. Live Activities are updated through it too, from structured fields the relay bounds. Ships as the `koan-push-relay` image and the `@radiosilence/koan-relay-pulumi` component.
