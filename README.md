# koan-push-relay

The push relay at `push.koan.rocks`. Apple delivers pushes to the [kōan](https://github.com/radiosilence/koan) iOS app only when they are signed with the developer's key, so a self-hosted kōan server cannot wake a phone or ask it to play. The relay holds that key and forwards pushes for any server, while deciding itself everything a phone is shown: servers hold sealed handles rather than device tokens, choose only the kind of push and an encrypted blob, and are held to quotas built around Apple's rules for the developer's account.

`docs/push-relay.md` specifies the API, what the relay sees and keeps, and how to run and deploy it.

It ships as a container image (`ghcr.io/radiosilence/koan-push-relay`), a static Linux binary on each GitHub release, and a Pulumi package (`@radiosilence/koan-relay-pulumi`, in `deploy/pulumi`) that deploys that image. `koan-relay-client` (`crates/koan-relay-client`) is the crate kōan's apps and servers call the relay through, published to crates.io with each release.
