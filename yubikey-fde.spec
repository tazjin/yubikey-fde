Summary: Full-disk-encryption with Yubikeys
Name: yubikey-fde
Version: master
Release: 1
License: MIT
Group: Applications/System
URL: https://github.com/tazjin/yubikey-fde
Source: %{name}-%{version}.tar.gz
BuildRequires: ykpers-devel
Requires: ykpers

%description
This tool handles using Yubikey HMAC-SHA1 challenge-response as LUKS encryption
keys. It comes with a systemd unit and dracut module to facilitate this.

%prep
%setup -q

%build
cargo build --release
gzip docs/yubikey-fde.8

%install
install -Dm644 "docs/yubikey-fde.8.gz" "%{buildroot}%{_mandir}/man8/yubikey-fde.8"
pwd
install -Dm755 "target/release/yubikey-fde" "%{buildroot}/usr/bin/yubikey-fde"
install -Dm644 "systemd/ykfde.dracut" \
        "%{buildroot}/usr/lib/dracut/modules.d/98ykfde/module-setup.sh"
install -Dm644 "systemd/systemd-ask-ykfde.path" \
        "%{buildroot}/usr/lib/systemd/system/systemd-ask-ykfde.path"
install -Dm644 "systemd/systemd-ask-ykfde.service" \
        "%{buildroot}/usr/lib/systemd/system/systemd-ask-ykfde.service"

%files
%doc README.md
%doc /usr/share/man/man8/yubikey-fde.8.gz
/usr/bin/yubikey-fde
/usr/lib/systemd/system/systemd-ask-ykfde.path
/usr/lib/systemd/system/systemd-ask-ykfde.service
/usr/lib/dracut/modules.d/98ykfde/module-setup.sh

%clean
cargo clean
rm docs/yubikey-fde.8.gz
