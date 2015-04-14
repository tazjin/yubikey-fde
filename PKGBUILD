# Maintainer:  Vincent Ambo <tazjin@gmail.com>
pkgname=yubikey-fde-git
pkgver=git
pkgrel=1
pkgdesc="Full disk encryption with Yubikeys"
arch=('i686' 'x86_64')
url="https://github.com/tazjin/yubikey-fde"
license=('MIT')
depends=('yubikey-personalization-git')
makedepends=('rust' 'cargo-bin')
source=('git+https://github.com/tazjin/yubikey-fde.git')
md5sums=('SKIP') # Because git

pkgver() {
  cd "$srcdir/yubikey-fde"
  printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
  cd "$srcdir/yubikey-fde"
  cargo build --release
}

package() {
  cd "$srcdir/yubikey-fde"

  install -Dm644 LICENSE "${pkgdir}/usr/share/licenses/yubikey-fde/LICENSE"
  install -Dm644 "docs/yubikey-fde.8" "${pkgdir}/usr/share/man/man8/yubikey-fde.8"
  install -Dm755 "target/release/yubikey-fde" "${pkgdir}/usr/bin/yubikey-fde"
  install -Dm644 "systemd/sd-ykfde" "${pkgdir}/usr/lib/initcpio/install/sd-ykfde"
  install -Dm644 "systemd/systemd-ask-ykfde.path" "${pkgdir}/usr/lib/systemd/system/systemd-ask-ykfde.path"
  install -Dm644 "systemd/systemd-ask-ykfde.service" "${pkgdir}/usr/lib/systemd/system/systemd-ask-ykfde.service"
}
