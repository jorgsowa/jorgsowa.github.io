#!/bin/sh
# Collects raw SBOM data for each PHP 8.5 build and architecture into $1 (default: ./raw).
set -u
OUT=${1:-raw}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"

DEB_EXT="cli curl mbstring xml intl gd zip mysql pgsql sqlite3 bcmath readline"
APK_EXT="curl mbstring xml dom simplexml xmlreader xmlwriter intl gd zip mysqli pdo pdo_mysql pgsql pdo_pgsql pdo_sqlite sqlite3 bcmath ctype fileinfo tokenizer session iconv openssl phar sodium"
RPM_PKGS="php-cli php-common php-mbstring php-xml php-intl php-gd php-pdo php-mysqlnd php-pgsql php-bcmath php-sodium php-process"
SURY="apt-get -qq update && apt-get -qq install -y curl ca-certificates \
  && curl -sSLo /tmp/sury.deb https://packages.sury.org/debsuryorg-archive-keyring.deb && dpkg -i /tmp/sury.deb \
  && echo 'deb [signed-by=/usr/share/keyrings/debsuryorg-archive-keyring.gpg] https://packages.sury.org/php/ trixie main' > /etc/apt/sources.list.d/php.list"

TIMEOUT=$(command -v gtimeout || command -v timeout)

deb_pkgs() { for e in $DEB_EXT; do printf 'php8.5-%s ' "$e"; done; }
apk_pkgs() { printf 'php85 '; for e in $APK_EXT; do printf 'php85-%s ' "$e"; done; }

run() {
  id=$1 arch=$2 image=$3 setup=$4 php=$5
  echo "== $id ($arch)"
  $TIMEOUT 900 docker run --rm --platform "linux/$arch" -v "$HERE":/c:ro -e DEBIAN_FRONTEND=noninteractive "$image" \
    sh -c "{ $setup; } >/dev/null 2>&1; $php /c/collect.php" > "$OUT/$id-$arch.json" \
    || { echo "FAILED: $id $arch"; rm -f "$OUT/$id-$arch.json"; }
}

for arch in amd64 arm64; do
  run docker-debian "$arch" php:8.5-cli \
    "apt-get -qq update && apt-get -qq install -y binutils" php
  run docker-alpine "$arch" php:8.5-cli-alpine \
    "apk add -q binutils" php
  run debian-13-sury "$arch" debian:trixie \
    "$SURY && apt-get -qq update && apt-get -qq install -y binutils $(deb_pkgs)" php8.5
  run ubuntu-26.04 "$arch" ubuntu:26.04 \
    "apt-get -qq update && apt-get -qq install -y binutils $(deb_pkgs)" php8.5
  run alpine-3.24 "$arch" alpine:3.24 \
    "apk add -q binutils $(apk_pkgs)" php85
  run fedora-44 "$arch" fedora:44 \
    "dnf -q -y install binutils $RPM_PKGS" php
done
