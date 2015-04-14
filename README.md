Yubikey FDE
===========

[![Build Status](https://travis-ci.org/tazjin/yubikey-fde.svg)](https://travis-ci.org/tazjin/yubikey-fde)

(Note that Travis builds are failing due to an [upstream blocker][]).

## Overview

This project aims to provide reliable full-disk-encryption using Yubikey challenge-response functionality.

A challenge is generated and stored on the machine to be encrypted. This challenge is sent to the Yubikey
which contains a secret key. The Yubikey returns `SHA1(HMAC(key, challenge))` as the response, and this
response is used as a [LUKS][] key.

Then `yubikey-fde` and its `systemd` units are included in the initial `initramfs`. Running `systemd` in
the image is a dependency because this tool is tailored towards it.

Once `systemd` encounters an encrypted device it will request a password, this request is picked up by
the application and if **a)** a challenge file is present and **b)** a Yubikey is plugged in the tool will
perform the challenge-response and respond to `systemd`. In case of this failing, `systemd` will still be
sending its password request to the console so that a recover is possible with a key from a different key
slot.

## Building

If you are on ArchLinux, you should be able to just run `makepkg`. You will need to have `rust` as well as
`cargo-bin` and `yubikey-personalization-git` from AUR installed.

On other systems, ensure you have the equivalents to those dependencies and run `cargo build` to build the
program. You will need to set up `systemd` units and `initramfs` generation manually, though Dracut support
is [in the works][].

This is intended to replace the programs in [mkinitcpio-ykfde][].

[upstream blocker]: https://github.com/travis-ci/travis-ci/issues/3632
[LUKS]: https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup
[in the works]: https://github.com/tazjin/yubikey-fde/issues/9
[mkinitcpio-ykfde]: https://github.com/eworm-de/mkinitcpio-ykfde
