#!/usr/bin/env python3
"""Fail-closed verification for Prodysor bootstrap releases and APKs."""

import argparse
import hashlib
import json
import posixpath
import re
import shlex
import stat
import struct
import zipfile
from pathlib import Path
from xml.etree import ElementTree


PRODUCT_PREFIX = "/data/data/com.prodysor.term/files/usr"
PRODUCT_APP_ID = "com.prodysor.term"
APP_JAVA_NAMESPACE = "com.termux"
OLD_PREFIX = b"/data/data/com.termux"
ASSET_NAME = "bootstrap-aarch64.zip"
MAX_ARCHIVE_SIZE = 256 * 1024 * 1024
MAX_ENTRY_SIZE = 256 * 1024 * 1024
MAX_TOTAL_SIZE = 1024 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_RATIO = 1000


def fail(message):
    raise SystemExit(message)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_lock(path):
    values = {}
    for line_number, raw_line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(f"Malformed lock line {line_number}")
        key, value = line.split("=", 1)
        if key in values:
            fail(f"Duplicate lock key: {key}")
        values[key] = value

    if set(values) != {"packageCommit", "sha256"}:
        fail("Lock must contain exactly packageCommit and sha256")
    if not re.fullmatch(r"[0-9a-f]{40}", values["packageCommit"]):
        fail("packageCommit must be a lowercase full Git commit SHA")
    if not re.fullmatch(r"[0-9a-f]{64}", values["sha256"]):
        fail("sha256 must be a lowercase SHA-256 digest")
    return values


def normalized_member_path(name, *, allow_leading_dot=False, allow_trailing_slash=False):
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        fail(f"Unsafe archive path: {name!r}")
    if re.match(r"^[A-Za-z]:", name):
        fail(f"Drive-qualified archive path: {name!r}")
    if allow_leading_dot and name.startswith("./"):
        name = name[2:]
    if allow_trailing_slash and name.endswith("/"):
        name = name[:-1]
    parts = name.split("/")
    if not name or any(part in ("", ".", "..") for part in parts):
        fail(f"Unsafe archive path component: {name!r}")
    return "/".join(parts)


def path_is_inside(path, root):
    return path == root or path.startswith(root + "/")


def verify_local_zip_headers(raw_archive, infos, central_directory_offset):
    """Require the streaming local-entry view to exactly match the central directory."""
    offset = 0
    local_header = struct.Struct("<IHHHHHIIIHH")
    for info in infos:
        if offset + local_header.size > central_directory_offset:
            fail("ZIP local entry table is truncated")
        fields = local_header.unpack_from(raw_archive, offset)
        signature, _, flags, method, _, _, crc, compressed_size, file_size, name_size, extra_size = fields
        if signature != 0x04034B50:
            fail(f"Unexpected data before ZIP local entry at offset {offset}")
        if flags & 0x08:
            fail("ZIP data descriptors are forbidden")
        name_start = offset + local_header.size
        name_end = name_start + name_size
        data_start = name_end + extra_size
        data_end = data_start + compressed_size
        if data_end > central_directory_offset:
            fail("ZIP local entry extends into the central directory")
        encoding = "utf-8" if flags & 0x800 else "cp437"
        try:
            local_name = raw_archive[name_start:name_end].decode(encoding)
        except UnicodeDecodeError as error:
            fail(f"ZIP local filename is not valid {encoding}: {error}")
        if info.header_offset != offset or local_name != info.filename:
            fail(f"ZIP local/central entry mismatch at offset {offset}: {local_name!r}")
        if (
            flags != info.flag_bits or method != info.compress_type or crc != info.CRC or
            compressed_size != info.compress_size or file_size != info.file_size
        ):
            fail(f"ZIP local/central metadata mismatch: {local_name!r}")
        offset = data_end

    if offset != central_directory_offset:
        fail("ZIP contains an unindexed local entry, prefix, or gap")


def verify_release(args):
    lock = load_lock(args.lock)
    release = json.loads(Path(args.release_json).read_text(encoding="utf-8"))
    tag = json.loads(Path(args.tag_json).read_text(encoding="utf-8"))
    expected_tag = f"product-bootstrap-aarch64-{lock['packageCommit']}"
    assets = release.get("assets", [])

    if release.get("draft") is not False or release.get("prerelease") is not True:
        fail("Bootstrap release must be a published prerelease")
    if release.get("immutable") is not True or not release.get("published_at"):
        fail("Bootstrap release is not immutable and published")
    if release.get("tag_name") != expected_tag:
        fail("Bootstrap release tag does not match the lock")
    if tag.get("object", {}).get("type") != "commit" or tag.get("object", {}).get("sha") != lock["packageCommit"]:
        fail("Bootstrap tag is not a lightweight ref to the locked commit")
    if len(assets) != 1:
        fail("Bootstrap release must contain exactly one asset")

    asset = assets[0]
    if asset.get("name") != ASSET_NAME or asset.get("state") != "uploaded":
        fail("Bootstrap release asset name or state is invalid")
    if asset.get("digest") != f"sha256:{lock['sha256']}":
        fail("Bootstrap release asset digest does not match the lock")
    if (
        not isinstance(asset.get("id"), int) or
        not isinstance(asset.get("size"), int) or
        asset["size"] <= 0 or
        asset["size"] > MAX_ARCHIVE_SIZE
    ):
        fail("Bootstrap release asset metadata is invalid")

    print(json.dumps({"asset_id": asset["id"], "asset_size": asset["size"], "tag": expected_tag}))


def verify_bootstrap(args):
    lock = load_lock(args.lock)
    archive_path = Path(args.archive)
    archive_size = archive_path.stat().st_size
    if archive_size <= 0 or archive_size > MAX_ARCHIVE_SIZE:
        fail(f"Bootstrap archive size is outside policy: {archive_size}")
    actual_sha = sha256(archive_path)
    if actual_sha != lock["sha256"]:
        fail(f"Bootstrap SHA mismatch: {actual_sha}")

    raw_archive = archive_path.read_bytes()
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ENTRIES:
            fail(f"Bootstrap entry count is outside policy: {len(infos)}")

        members = {}
        total_size = 0
        for info in infos:
            name = normalized_member_path(
                info.filename, allow_leading_dot=False, allow_trailing_slash=info.is_dir()
            )
            if name in members:
                fail(f"Duplicate normalized ZIP member: {name!r}")
            if info.flag_bits & 1:
                fail(f"Encrypted ZIP member is forbidden: {name!r}")
            if info.flag_bits & 0x08:
                fail(f"ZIP data descriptor is forbidden: {name!r}")
            mode = info.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                fail(f"Non-regular ZIP member is forbidden: {name!r}")
            if info.file_size > MAX_ENTRY_SIZE:
                fail(f"ZIP member is too large: {name!r}")
            if info.file_size and info.file_size / max(1, info.compress_size) > MAX_RATIO:
                fail(f"ZIP compression ratio is too high: {name!r}")
            total_size += info.file_size
            if total_size > MAX_TOTAL_SIZE:
                fail("Bootstrap unpacked size exceeds policy")
            members[name] = info

        verify_local_zip_headers(raw_archive, infos, archive.start_dir)
        bad_crc = archive.testzip()
        if bad_crc is not None:
            fail(f"Bootstrap CRC failure: {bad_crc!r}")

        required = {
            "bin/bash",
            "bin/termux-open",
            "bin/termux-reload-settings",
            "bin/termux-reset",
            "bin/termux-setup-storage",
            "bin/termux-wake-lock",
            "bin/termux-wake-unlock",
            "etc/apt/sources.list",
            "etc/termux/termux-bootstrap/second-stage/termux-bootstrap-second-stage.sh",
            "SYMLINKS.txt",
            "var/lib/dpkg/status",
        }
        missing = required.difference(members)
        if missing:
            fail(f"Bootstrap is missing required members: {sorted(missing)}")

        service_component = f"{PRODUCT_APP_ID}/{APP_JAVA_NAMESPACE}.app.TermuxService".encode()
        receiver_component = f"{PRODUCT_APP_ID}/{APP_JAVA_NAMESPACE}.app.TermuxOpenReceiver".encode()
        reload_action = f"{PRODUCT_APP_ID}.app.reload_style".encode()
        expected_runtime_values = {
            "bin/termux-wake-lock": service_component,
            "bin/termux-wake-unlock": service_component,
            "bin/termux-reset": service_component,
            "bin/termux-open": receiver_component,
            "bin/termux-setup-storage": reload_action,
            "bin/termux-reload-settings": reload_action,
        }
        for name, expected_value in expected_runtime_values.items():
            if expected_value not in archive.read(members[name]):
                fail(f"Product Android target is missing or incorrect in bootstrap member: {name!r}")

        symlinks_text = archive.read(members["SYMLINKS.txt"]).decode("utf-8")
        symlink_destinations = set()
        for line_number, line in enumerate(symlinks_text.splitlines(), 1):
            parts = line.split("←")
            if len(parts) != 2 or not parts[0] or not parts[1]:
                fail(f"Malformed SYMLINKS.txt line {line_number}")
            target, destination = parts
            destination = normalized_member_path(destination, allow_leading_dot=True)
            if destination in symlink_destinations:
                fail(f"Duplicate symlink destination: {destination!r}")
            if destination in members:
                fail(f"Symlink destination collides with ZIP member: {destination!r}")
            symlink_destinations.add(destination)

            link_path = posixpath.join(PRODUCT_PREFIX, destination)
            if target.startswith("/"):
                resolved_target = posixpath.normpath(target)
            else:
                resolved_target = posixpath.normpath(posixpath.join(posixpath.dirname(link_path), target))
            if not path_is_inside(resolved_target, PRODUCT_PREFIX):
                fail(f"Symlink target escapes product prefix on line {line_number}: {target!r}")

        if not symlink_destinations:
            fail("SYMLINKS.txt contains no entries")

        second_stage = archive.read(
            members["etc/termux/termux-bootstrap/second-stage/termux-bootstrap-second-stage.sh"]
        )
        if PRODUCT_PREFIX.encode() not in second_stage:
            fail("Product prefix is missing from second-stage bootstrap")
        if b'export TERMUX_PACKAGE_ARCH="aarch64"' not in second_stage:
            fail("aarch64 marker is missing from second-stage bootstrap")

        sources = archive.read(members["etc/apt/sources.list"]).decode("utf-8")
        source_files = sorted(
            name for name in members
            if name == "etc/apt/sources.list" or
            (name.startswith("etc/apt/sources.list.d/") and name.endswith((".list", ".sources")))
        )
        if source_files != ["etc/apt/sources.list"]:
            fail(f"Unexpected additional APT source files: {source_files}")
        enabled_sources = []
        for raw_line in sources.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if re.match(r"^deb(?:\s|$)", line):
                enabled_sources.append(line)
        if len(enabled_sources) != 1:
            fail(f"Expected exactly one enabled APT source, found {len(enabled_sources)}")
        expected_repository = "https://prodysor.github.io/termux-repo/apt/termux-main/"
        expected_key = f"signed-by={PRODUCT_PREFIX}/share/keyrings/prodysor-archive-keyring.gpg"
        source_match = re.fullmatch(r"deb\s+\[([^]]+)]\s+(\S+)\s+(\S+)\s+(.+)", enabled_sources[0])
        if source_match is None:
            fail("APT source does not use the required deb/options/URI/suite/components form")
        options, repository, suite, components = source_match.groups()
        try:
            parsed_options = shlex.split(options)
            parsed_components = shlex.split(components)
        except ValueError as error:
            fail(f"Malformed APT source: {error}")
        if (
            parsed_options != [expected_key] or repository != expected_repository or
            suite != "stable" or parsed_components != ["main"]
        ):
            fail("APT source is not constrained to the Prodysor repository and key")

        elf_files = 0
        for name, info in members.items():
            if info.is_dir():
                continue
            data = archive.read(info)
            if OLD_PREFIX in data:
                fail(f"Official Termux prefix remains in bootstrap member: {name!r}")
            if name.startswith("etc/apt/") and re.search(
                rb"packages(?:-cf)?\.termux\.dev|termux\.net", data
            ):
                fail(f"Official Termux repository remains in APT config: {name!r}")
            if data.startswith(b"\x7fELF"):
                elf_files += 1
                if len(data) < 20 or data[4] != 2 or data[5] != 1:
                    fail(f"Malformed or non-little-endian ELF64 in bootstrap: {name!r}")
                if struct.unpack("<H", data[18:20])[0] != 183:
                    fail(f"Non-AArch64 ELF in bootstrap: {name!r}")

        if elf_files == 0:
            fail("Bootstrap contains no ELF executables")

        status = archive.read(members["var/lib/dpkg/status"]).decode("utf-8", errors="strict")
        architectures = set(re.findall(r"(?m)^Architecture:\s*(\S+)\s*$", status))
        if not architectures or not architectures.issubset({"aarch64", "all"}):
            fail(f"Unexpected installed package architectures: {sorted(architectures)}")

    print(json.dumps({
        "archive_sha256": actual_sha,
        "archive_size": archive_size,
        "entries": len(infos),
        "symlinks": len(symlink_destinations),
    }))


def verify_apk(args):
    lock = load_lock(args.lock)
    apk_path = Path(args.apk)
    bootstrap = Path(args.bootstrap).read_bytes()
    if hashlib.sha256(bootstrap).hexdigest() != lock["sha256"]:
        fail("Bootstrap passed to APK verifier does not match the lock")

    android_attribute = "{http://schemas.android.com/apk/res/android}"
    manifest = ElementTree.parse(args.manifest_xml).getroot()
    if manifest.get("package") != PRODUCT_APP_ID:
        fail(f"Merged manifest package is not {PRODUCT_APP_ID}")
    if android_attribute + "sharedUserId" in manifest.attrib:
        fail("Merged manifest must not declare android:sharedUserId")
    application = manifest.find("application")
    if application is None:
        fail("Merged manifest has no application element")
    if application.get(android_attribute + "name") != f"{APP_JAVA_NAMESPACE}.app.TermuxApplication":
        fail("Merged manifest application class does not match the retained Java namespace")

    declared_permissions = [
        element.get(android_attribute + "name") for element in manifest.findall("permission")
    ]
    expected_run_permission = f"{PRODUCT_APP_ID}.permission.RUN_COMMAND"
    if expected_run_permission not in declared_permissions:
        fail("Merged manifest does not declare the product RUN_COMMAND permission")

    service_names = [
        element.get(android_attribute + "name") for element in application.findall("service")
    ]
    if f"{APP_JAVA_NAMESPACE}.app.TermuxService" not in service_names:
        fail("Merged manifest does not contain the TermuxService implementation class")
    run_command_services = [
        element for element in application.findall("service")
        if element.get(android_attribute + "name") == f"{APP_JAVA_NAMESPACE}.app.RunCommandService"
    ]
    if len(run_command_services) != 1 or run_command_services[0].get(
        android_attribute + "permission"
    ) != expected_run_permission:
        fail("Merged manifest RUN_COMMAND service or permission is invalid")
    run_command_actions = [
        action.get(android_attribute + "name")
        for intent_filter in run_command_services[0].findall("intent-filter")
        for action in intent_filter.findall("action")
    ]
    if f"{PRODUCT_APP_ID}.RUN_COMMAND" not in run_command_actions:
        fail("Merged manifest RUN_COMMAND action is not product-scoped")

    receiver_names = [
        element.get(android_attribute + "name") for element in application.findall("receiver")
    ]
    if f"{APP_JAVA_NAMESPACE}.app.TermuxOpenReceiver" not in receiver_names:
        fail("Merged manifest does not contain the TermuxOpenReceiver implementation class")

    matching_metadata = [
        element for element in application.findall("meta-data")
        if element.get(android_attribute + "name") == "com.prodysor.term.bootstrap.SHA256"
    ]
    if len(matching_metadata) != 1 or matching_metadata[0].get(android_attribute + "value") != lock["sha256"]:
        fail("Merged manifest bootstrap SHA metadata does not match the lock")
    authorities = [
        provider.get(android_attribute + "authorities") for provider in application.findall("provider")
    ]
    split_authorities = [
        authority for declaration in authorities if declaration for authority in declaration.split(";")
    ]
    if not split_authorities or any(
        not authority.startswith("com.prodysor.term.") for authority in split_authorities
    ):
        fail(f"Merged manifest contains an unexpected provider authority: {authorities}")

    with zipfile.ZipFile(apk_path) as apk:
        bad_crc = apk.testzip()
        if bad_crc is not None:
            fail(f"APK CRC failure: {bad_crc!r}")
        native_files = [info for info in apk.infolist() if info.filename.startswith("lib/") and not info.is_dir()]
        if not native_files:
            fail("APK has no native libraries")
        if any(not info.filename.startswith("lib/arm64-v8a/") for info in native_files):
            fail("APK contains a non-ARM64 native library path")

        for info in native_files:
            data = apk.read(info)
            if len(data) < 20 or data[:4] != b"\x7fELF":
                fail(f"Native library is not ELF: {info.filename!r}")
            if data[4] != 2 or data[5] != 1 or struct.unpack("<H", data[18:20])[0] != 183:
                fail(f"Native library is not AArch64: {info.filename!r}")

        bootstrap_library_name = "lib/arm64-v8a/libtermux-bootstrap.so"
        try:
            bootstrap_library = apk.read(bootstrap_library_name)
        except KeyError:
            fail(f"APK is missing {bootstrap_library_name}")
        if bootstrap_library.count(bootstrap) != 1:
            fail("Locked bootstrap bytes do not occur exactly once in libtermux-bootstrap.so")

        for info in apk.infolist():
            if not info.is_dir() and OLD_PREFIX in apk.read(info):
                fail(f"Official Termux prefix remains in APK entry: {info.filename!r}")

    print(json.dumps({"apk_sha256": sha256(apk_path), "apk_size": apk_path.stat().st_size}))


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    release = subparsers.add_parser("release")
    release.add_argument("--lock", required=True)
    release.add_argument("--release-json", required=True)
    release.add_argument("--tag-json", required=True)
    release.set_defaults(handler=verify_release)

    bootstrap = subparsers.add_parser("bootstrap")
    bootstrap.add_argument("--lock", required=True)
    bootstrap.add_argument("--archive", required=True)
    bootstrap.set_defaults(handler=verify_bootstrap)

    apk = subparsers.add_parser("apk")
    apk.add_argument("--lock", required=True)
    apk.add_argument("--bootstrap", required=True)
    apk.add_argument("--apk", required=True)
    apk.add_argument("--manifest-xml", required=True)
    apk.set_defaults(handler=verify_apk)

    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
