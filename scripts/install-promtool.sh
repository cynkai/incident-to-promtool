#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'install-promtool: %s\n' "$*" >&2
    exit 1
}

if [[ $# -ne 2 || -z ${2:-} ]]; then
    printf 'Usage: bash scripts/install-promtool.sh VERSION DESTINATION_DIR\n' >&2
    exit 2
fi

version=$1
destination=$2
case "$version" in
    3.9.0) sha256=27c7438ffbd2a99a25b14e5b1540bdc4f14519b5c5495efad537a61296075198 ;;
    3.11.0) sha256=ff799c3e4c318e17dec14aaaa406a4da328fabb4578336b36d96d893870c3b76 ;;
    *) fail "unsupported promtool version '$version' (choose 3.9.0 or 3.11.0 without a v prefix)" ;;
esac

platform=$(uname -s)
architecture=$(uname -m)
if [[ $platform != Linux || $architecture != x86_64 ]]; then
    fail "unsupported platform '$platform $architecture' (requires Linux x86_64)"
fi

for tool in curl sha256sum tar mktemp install; do
    command -v "$tool" >/dev/null || fail "required command not found: $tool"
done

temporary=$(mktemp -d) || fail "could not make a temporary download directory"
staged=
cleanup() {
    if [[ -n $staged ]]; then
        rm -f -- "$staged"
    fi
    rm -rf -- "$temporary"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

asset="prometheus-${version}.linux-amd64"
archive="$temporary/promtool.tar.gz"
url="https://github.com/prometheus/prometheus/releases/download/v${version}/${asset}.tar.gz"
curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 120 --retry 3 --output "$archive" "$url" \
    || fail "could not download official Prometheus release v$version"

if ! (cd -- "$temporary" && printf '%s  promtool.tar.gz\n' "$sha256" | sha256sum --check --status); then
    fail "SHA-256 verification failed for the Prometheus v$version archive"
fi

tar --extract --gzip --file "$archive" --directory "$temporary" --strip-components=1 -- "$asset/promtool" \
    || fail "could not extract promtool from the verified release archive"
mkdir -p -- "$destination" || fail "could not create destination directory '$destination'"
staged=$(mktemp -- "${destination%/}/.promtool.XXXXXXXX") || fail "could not stage promtool in '$destination'"
install -m 0755 -- "$temporary/promtool" "$staged" || fail "could not prepare the promtool executable"
mv -fT -- "$staged" "$destination/promtool" || fail "could not install promtool in '$destination'"
