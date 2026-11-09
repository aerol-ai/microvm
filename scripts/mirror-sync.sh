#!/usr/bin/env bash
# mirror-sync.sh copies downloads to the public mirror that install.sh falls
# back to when GitHub fails (s3://aerolvm-downloads, us-east-1).
#
#   scripts/mirror-sync.sh --release <tag> [--latest | --no-latest]
#   scripts/mirror-sync.sh --deps [--check]
#
# Options for both: --bucket <name>, --region <region>, --dry-run, --force,
# --repo <owner/repo> (releases only), --install-sh <path> (deps only).
#
# --release downloads every file of an AerolVM release with gh, checks each
# one against the release's checksums.txt, and uploads them all to
# s3://<bucket>/aerolvm/<tag>/ under the same names. Then, if <tag> is
# GitHub's latest release (or with --latest), it points aerolvm/latest.txt
# at it: install.sh reads that to find "latest" on the mirror.
#
# --deps downloads every third-party file listed by download_pins in
# install.sh, checks its pinned SHA-256, and uploads it to
# deps/<project>/<version>/<file>. The pins are read from install.sh itself
# (the DOWNLOAD PINS block), so the mirror and the installer cannot disagree.
# It first asks the public mirror which pinned files it already holds; when
# it holds all of them (the usual case: pins rarely change), it downloads and
# uploads nothing, so the release workflow can run it on every release.
#
# --deps --check only asks: it lists every pinned file the public mirror
# lacks and exits 1 if there is one. It needs curl and nothing else (no AWS
# credentials, no gh), so a pull request check can run it.
#
# A file already on the mirror at the same size is not uploaded again, so a
# re-run (or a release workflow re-running) sends only what is missing; on
# 2026-11-08 a plain sync re-sent all of v0.6.11 because every freshly
# downloaded file looked newer. Deps paths are versioned and never change in
# place. A release re-cut under the same tag can change a file and keep its
# size, so when the mirror's checksums.txt for the tag differs from the
# release's, every file is sent. --force sends every file in any case.
#
# Nothing is uploaded unless every file checked out. --dry-run prints the
# plan and downloads or uploads nothing. Uploading needs AWS credentials
# that can write to the bucket; downloading needs gh logged in (GH_TOKEN in
# CI). GitHub release files are fetched through gh's API path rather than
# the github.com download links, which is what failed on 2026-11-08.
set -euo pipefail

BUCKET="aerolvm-downloads"
REGION="us-east-1"
REPO="aerol-ai/microvm"
MODE=""
TAG=""
LATEST="auto"
DRY_RUN="false"
CHECK="false"
FORCE="false"
INSTALL_SH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install.sh"

TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'

usage() {
	sed -n '2,/^set -euo pipefail$/{/^set /d;s/^# \{0,1\}//;p;}' "${BASH_SOURCE[0]}"
}

die() {
	echo "mirror-sync: $*" >&2
	exit 1
}

need() {
	local tool
	for tool in "$@"; do
		command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
	done
}

sha256_of() {
	local out
	if command -v sha256sum >/dev/null 2>&1; then
		out="$(sha256sum "$1")"
	else
		out="$(shasum -a 256 "$1")"
	fi
	echo "${out%% *}"
}

# check_release verifies a downloaded release directory: every file listed in
# checksums.txt is present with that SHA-256, and every file present is
# listed, apart from checksums.txt itself and the provenance bundle
# (<tag>.intoto.jsonl), which release.yml adds after writing checksums.txt
# and which is signed on its own.
check_release() {
	local dir="$1" tag="$2" sum name want got bad=0
	[[ -s "$dir/checksums.txt" ]] || die "$tag has no checksums.txt; nothing uploaded"
	while read -r sum name; do
		[[ -n "$sum" ]] || continue
		name="${name#\*}"
		if [[ ! "$name" =~ ^[A-Za-z0-9._-]+$ ]]; then
			echo "mirror-sync: checksums.txt names an unexpected file: $name" >&2
			bad=1
			continue
		fi
		if [[ ! -f "$dir/$name" ]]; then
			echo "mirror-sync: $name is in checksums.txt but not in the release" >&2
			bad=1
			continue
		fi
		got="$(sha256_of "$dir/$name")"
		if [[ "$got" != "$sum" ]]; then
			echo "mirror-sync: $name does not match checksums.txt: got $got, want $sum" >&2
			bad=1
		fi
	done <"$dir/checksums.txt"
	for name in "$dir"/*; do
		name="${name##*/}"
		case "$name" in
			checksums.txt | "${tag}.intoto.jsonl") continue ;;
		esac
		want="$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1 }' "$dir/checksums.txt")"
		if [[ -z "$want" ]]; then
			echo "mirror-sync: $name is in the release but not in checksums.txt" >&2
			bad=1
		fi
	done
	((bad == 0)) || die "$tag did not check out against its checksums.txt; nothing uploaded"
}

sync_release() {
	local tag="$1"
	[[ "$tag" =~ $TAG_RE ]] || die "--release needs a tag like v1.2.3 (got $tag)"
	need gh
	local dest="s3://${BUCKET}/aerolvm/${tag}/"
	local mark="$LATEST"
	if [[ "$mark" == "auto" ]]; then
		local latest
		latest="$(gh release view --repo "$REPO" --json tagName --jq .tagName)" ||
			die "cannot ask GitHub which release is latest; pass --latest or --no-latest"
		if [[ "$latest" == "$tag" ]]; then
			mark="yes"
		else
			mark="no"
			echo "GitHub's latest release is ${latest}, so aerolvm/latest.txt stays as it is."
		fi
	fi

	if [[ "$DRY_RUN" == "true" ]]; then
		echo "Plan: copy ${REPO} ${tag} to ${dest}"
		gh release view "$tag" --repo "$REPO" --json assets --jq '.assets[].name' | while read -r name; do
			echo "  ${name} -> ${dest}${name}"
		done
		echo "  each checked against the release's checksums.txt first"
		if [[ "$mark" == "yes" ]]; then
			echo "Then point s3://${BUCKET}/aerolvm/latest.txt at ${tag}."
		fi
		return 0
	fi

	need aws
	local dir="$WORK/release"
	mkdir -p "$dir"
	echo "Downloading ${REPO} ${tag}"
	gh release download "$tag" --repo "$REPO" --dir "$dir"
	check_release "$dir" "$tag"
	echo "Every file of ${tag} matches its checksums.txt; uploading to ${dest}"
	local opts=("${SYNC_OPTS[@]}")
	# A release re-cut under the same tag can change a file without changing
	# its size, and checksums.txt never changes size (fixed-length lines), so
	# a size-only sync would leave the mirror's checksums.txt stale against
	# its new files and every install from the mirror would fail its check.
	# When the mirror's checksums.txt differs from the release's, send every
	# file, as --force does.
	if [[ "$FORCE" != "true" ]] && aws s3 cp "${dest}checksums.txt" "$WORK/mirror-checksums.txt" \
		--region "$REGION" --only-show-errors --no-progress 2>/dev/null; then
		if ! cmp -s "$WORK/mirror-checksums.txt" "$dir/checksums.txt"; then
			echo "The mirror's checksums.txt for ${tag} differs from the release's (re-cut?); sending every file"
			opts=(--region "$REGION" --only-show-errors --no-progress)
		fi
	fi
	aws s3 sync "$dir" "$dest" "${opts[@]}"
	if [[ "$mark" == "yes" ]]; then
		printf '%s\n' "$tag" >"$WORK/latest.txt"
		# latest.txt moves only after every file of the release is up, so
		# an install that reads it never finds a release half uploaded.
		aws s3 cp "$WORK/latest.txt" "s3://${BUCKET}/aerolvm/latest.txt" --region "$REGION" \
			--content-type text/plain --cache-control no-cache --only-show-errors --no-progress
		echo "aerolvm/latest.txt now names ${tag}"
	fi
	echo "Done: ${tag} is on the mirror"
}

# load_pins runs install.sh's DOWNLOAD PINS block in this shell, which
# defines download_pins and the variables it reads.
load_pins() {
	[[ -f "$INSTALL_SH" ]] || die "no install.sh at $INSTALL_SH"
	local block
	block="$(sed -n '/^# --- BEGIN DOWNLOAD PINS/,/^# --- END DOWNLOAD PINS/p' "$INSTALL_SH")"
	[[ "$block" == *"# --- END DOWNLOAD PINS"* ]] || die "$INSTALL_SH has no DOWNLOAD PINS block"
	eval "$block"
	declare -F download_pins >/dev/null || die "the DOWNLOAD PINS block defines no download_pins"
}

# fetch_origin downloads one pin's origin URL to a file. A GitHub release
# file goes through gh (the API path); anything else through curl.
fetch_origin() {
	local url="$1" out="$2"
	local gh_re='^https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/releases/download/([^/]+)/([A-Za-z0-9._+-]+)$'
	if [[ "$url" =~ $gh_re ]]; then
		local repo="${BASH_REMATCH[1]}" tag="${BASH_REMATCH[2]}" file="${BASH_REMATCH[3]}"
		local tmp="$WORK/gh-download"
		rm -rf "$tmp"
		mkdir -p "$tmp"
		gh release download "$tag" --repo "$repo" --pattern "$file" --dir "$tmp" || return 1
		[[ -f "$tmp/$file" ]] || return 1
		mv "$tmp/$file" "$out"
	else
		curl -fsSL --retry 3 --retry-delay 5 --connect-timeout 20 -o "$out" "$url"
	fi
}

# public_base is where anyone reads the mirror over HTTPS (install.sh's
# default DOWNLOAD_MIRROR for the default bucket). MIRROR_SYNC_PUBLIC_BASE
# overrides it, for tests.
public_base() {
	echo "${MIRROR_SYNC_PUBLIC_BASE:-https://${BUCKET}.s3.${REGION}.amazonaws.com}"
}

# deps_missing prints the mirror key of every pinned file the public mirror
# does not serve. It reads each one's headers only.
deps_missing() {
	local base project version file sha origin key
	base="$(public_base)"
	while read -r project version file sha origin; do
		key="deps/${project}/${version}/${file}"
		# </dev/null: curl must not eat the rows this loop reads.
		if ! curl -fsSIL --retry 3 --retry-delay 2 --max-time 30 -o /dev/null "${base}/${key}" </dev/null; then
			echo "$key"
		fi
	done <<<"$1"
}

sync_deps() {
	load_pins
	local safe='^[A-Za-z0-9][A-Za-z0-9._+-]*$'
	local stage="$WORK/stage"
	local project version file sha origin key out src member got f count=0
	local rows
	rows="$(download_pins)"
	[[ -n "$rows" ]] || die "download_pins listed nothing"
	local missing total
	total="$(grep -c . <<<"$rows")"
	if [[ "$CHECK" == "true" || ("$DRY_RUN" != "true" && "$FORCE" != "true") ]]; then
		need curl
		missing="$(deps_missing "$rows")"
		if [[ -z "$missing" ]]; then
			echo "All ${total} pinned files are on the mirror ($(public_base)/deps/); nothing to do"
			return 0
		fi
		if [[ "$CHECK" == "true" ]]; then
			echo "The mirror lacks $(grep -c . <<<"$missing") of the ${total} files install.sh pins:" >&2
			sed 's/^/  /' <<<"$missing" >&2
			echo "Run scripts/mirror-sync.sh --deps with credentials that can write to s3://${BUCKET}/deps/ (the release workflow does this too)." >&2
			return 1
		fi
		echo "The mirror lacks $(grep -c . <<<"$missing") of the ${total} pinned files; checking and uploading"
	fi
	if [[ "$DRY_RUN" == "true" ]]; then
		echo "Plan: copy the files install.sh pins to s3://${BUCKET}/deps/"
	else
		need aws gh curl tar
	fi
	while read -r project version file sha origin; do
		for f in "$project" "$version" "$file"; do
			[[ "$f" =~ $safe ]] || die "download_pins has an unsafe path segment: $f"
		done
		[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "download_pins: $file has no SHA-256"
		key="deps/${project}/${version}/${file}"
		if [[ "$DRY_RUN" == "true" ]]; then
			echo "  ${origin} -> s3://${BUCKET}/${key} (sha256 ${sha})"
			continue
		fi
		out="$stage/$key"
		mkdir -p "${out%/*}"
		case "$origin" in
			tar:*)
				src="${origin#tar:}"
				member="${src#*:}"
				src="$stage/deps/${project}/${version}/${src%%:*}"
				# The source is listed (and so downloaded and checked) first.
				[[ -f "$src" ]] || die "$file: $origin names a file not downloaded before it"
				tar -xzf "$src" -O "$member" >"$out" </dev/null || die "$file: cannot take $member out of ${src##*/}"
				;;
			https://*)
				echo "Downloading ${origin}"
				# </dev/null: gh and curl must not eat the rows this loop reads.
				fetch_origin "$origin" "$out" </dev/null || die "cannot download $origin; nothing uploaded"
				;;
			*) die "$file: origin $origin is neither https:// nor tar:" ;;
		esac
		got="$(sha256_of "$out")"
		[[ "$got" == "$sha" ]] || die "$file does not match its pin: got $got, want $sha (from $origin); nothing uploaded"
		count=$((count + 1))
	done <<<"$rows"
	[[ "$DRY_RUN" == "true" ]] && return 0
	echo "All ${count} pinned files match; uploading to s3://${BUCKET}/deps/"
	aws s3 sync "$stage/deps" "s3://${BUCKET}/deps" "${SYNC_OPTS[@]}"
	echo "Done: ${count} files are on the mirror"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--release)
			[[ -z "$MODE" ]] || die "pass --release or --deps, not both"
			[[ $# -ge 2 ]] || die "--release needs a tag"
			MODE="release"
			TAG="$2"
			shift 2
			;;
		--deps)
			[[ -z "$MODE" ]] || die "pass --release or --deps, not both"
			MODE="deps"
			shift
			;;
		--latest) LATEST="yes"; shift ;;
		--no-latest) LATEST="no"; shift ;;
		--dry-run) DRY_RUN="true"; shift ;;
		--check) CHECK="true"; shift ;;
		--force) FORCE="true"; shift ;;
		--bucket)
			[[ $# -ge 2 && "$2" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] || die "--bucket needs an S3 bucket name"
			BUCKET="$2"
			shift 2
			;;
		--region)
			[[ $# -ge 2 && "$2" =~ ^[a-z0-9-]+$ ]] || die "--region needs an AWS region"
			REGION="$2"
			shift 2
			;;
		--repo)
			[[ $# -ge 2 && "$2" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "--repo needs owner/repo"
			REPO="$2"
			shift 2
			;;
		--install-sh)
			[[ $# -ge 2 ]] || die "--install-sh needs a path"
			INSTALL_SH="$2"
			shift 2
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			usage >&2
			die "unknown argument: $1"
			;;
	esac
done

[[ -n "$MODE" ]] || { usage >&2; die "pass --release <tag> or --deps"; }
if [[ "$MODE" == "deps" && "$LATEST" != "auto" ]]; then
	die "--latest and --no-latest go with --release"
fi
if [[ "$CHECK" == "true" && "$MODE" != "deps" ]]; then
	die "--check goes with --deps"
fi

# --size-only skips a file the mirror already holds at the same size; the
# default sync also re-sends any local file with a newer mtime, which is
# every file just downloaded.
SYNC_OPTS=(--region "$REGION" --only-show-errors --no-progress)
[[ "$FORCE" == "true" ]] || SYNC_OPTS+=(--size-only)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

case "$MODE" in
	release) sync_release "$TAG" ;;
	deps) sync_deps ;;
esac
