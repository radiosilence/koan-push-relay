# Changelog

## 0.1.0

### Added

- **Push relay.** Forwards pushes to Apple for kōan servers that do not hold the developer's key. Servers hold sealed handles instead of device tokens, and the relay writes the whole of what Apple is sent, within quotas built around Apple's rules for the developer's account. Live Activities are updated through it too, from structured fields the relay bounds. Ships as the `koan-push-relay` image and the `@radiosilence/koan-relay-pulumi` component.
