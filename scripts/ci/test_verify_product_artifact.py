#!/usr/bin/env python3

import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-product-artifact.py")
COMMIT = "a" * 40
PRODUCT_PREFIX = "/data/data/com.prodysor.term/files/usr"


class ProductArtifactVerifierTest(unittest.TestCase):

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def write_lock(self, digest):
        lock = self.root / "product-bootstrap.properties"
        lock.write_text(f"packageCommit={COMMIT}\nsha256={digest}\n", encoding="utf-8")
        return lock

    def write_bootstrap(self, *, member_name="share/example", symlink_target="bash", old_prefix=False,
                        source_line=None, component_namespace="com.termux"):
        archive = self.root / "bootstrap-aarch64.zip"
        elf_header = bytearray(20)
        elf_header[:6] = b"\x7fELF\x02\x01"
        elf_header[18:20] = struct.pack("<H", 183)
        if source_line is None:
            source_line = (
                f"deb [signed-by={PRODUCT_PREFIX}/share/keyrings/prodysor-archive-keyring.gpg] "
                "https://prodysor.github.io/termux-repo/apt/termux-main/ stable main"
            )
        members = {
            "bin/bash": bytes(elf_header),
            "bin/termux-open": (
                f"com.prodysor.term/{component_namespace}.app.TermuxOpenReceiver\n"
            ).encode(),
            "bin/termux-reload-settings": b"com.prodysor.term.app.reload_style\n",
            "bin/termux-reset": (
                f"com.prodysor.term/{component_namespace}.app.TermuxService\n"
            ).encode(),
            "bin/termux-setup-storage": b"com.prodysor.term.app.reload_style\n",
            "bin/termux-wake-lock": (
                f"com.prodysor.term/{component_namespace}.app.TermuxService\n"
            ).encode(),
            "bin/termux-wake-unlock": (
                f"com.prodysor.term/{component_namespace}.app.TermuxService\n"
            ).encode(),
            "etc/apt/sources.list": (source_line + "\n").encode(),
            "etc/termux/termux-bootstrap/second-stage/termux-bootstrap-second-stage.sh": (
                f'PREFIX="{PRODUCT_PREFIX}"\nexport TERMUX_PACKAGE_ARCH="aarch64"\n'
            ).encode(),
            "var/lib/dpkg/status": b"Package: bash\nArchitecture: aarch64\nStatus: install ok installed\n",
            "SYMLINKS.txt": f"{symlink_target}←./bin/sh\n".encode(),
            member_name: b"/data/data/com.termux" if old_prefix else b"safe",
        }
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for name, data in members.items():
                output.writestr(name, data)
        return archive

    def run_verifier(self, *arguments):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, arguments)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_accepts_safe_bootstrap(self):
        bootstrap = self.write_bootstrap()
        lock = self.write_lock(hashlib.sha256(bootstrap.read_bytes()).hexdigest())

        result = self.run_verifier("bootstrap", "--lock", lock, "--archive", bootstrap)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(hashlib.sha256(bootstrap.read_bytes()).hexdigest(), json.loads(result.stdout)["archive_sha256"])

    def test_rejects_archive_alias_old_prefix_and_escaping_symlink(self):
        cases = [
            {"member_name": "a/../alias"},
            {"old_prefix": True},
            {"symlink_target": "../../../home/owned"},
            {"component_namespace": "com.prodysor.term"},
        ]
        for case in cases:
            with self.subTest(case=case):
                bootstrap = self.write_bootstrap(**case)
                lock = self.write_lock(hashlib.sha256(bootstrap.read_bytes()).hexdigest())
                result = self.run_verifier("bootstrap", "--lock", lock, "--archive", bootstrap)
                self.assertNotEqual(0, result.returncode)

    def test_rejects_unindexed_local_entry(self):
        bootstrap = self.write_bootstrap()
        backdoor_name = b"bin/unverified-backdoor"
        backdoor_data = b"unverified"
        local_header = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50, 20, 0, 0, 0, 0, zlib.crc32(backdoor_data),
            len(backdoor_data), len(backdoor_data), len(backdoor_name), 0,
        )
        bootstrap.write_bytes(local_header + backdoor_name + backdoor_data + bootstrap.read_bytes())
        lock = self.write_lock(hashlib.sha256(bootstrap.read_bytes()).hexdigest())

        result = self.run_verifier("bootstrap", "--lock", lock, "--archive", bootstrap)

        self.assertNotEqual(0, result.returncode)

    def test_rejects_expected_apt_values_hidden_in_comment(self):
        source_line = (
            "deb [trusted=yes] https://evil.example.invalid stable main # "
            f"https://prodysor.github.io/termux-repo/apt/termux-main/ "
            f"signed-by={PRODUCT_PREFIX}/share/keyrings/prodysor-archive-keyring.gpg"
        )
        bootstrap = self.write_bootstrap(source_line=source_line)
        lock = self.write_lock(hashlib.sha256(bootstrap.read_bytes()).hexdigest())

        result = self.run_verifier("bootstrap", "--lock", lock, "--archive", bootstrap)

        self.assertNotEqual(0, result.returncode)

    def test_accepts_exact_immutable_release(self):
        digest = "b" * 64
        lock = self.write_lock(digest)
        tag_name = f"product-bootstrap-aarch64-{COMMIT}"
        release_json = self.root / "release.json"
        release_json.write_text(json.dumps({
            "draft": False,
            "prerelease": True,
            "immutable": True,
            "published_at": "2026-09-06T00:00:00Z",
            "tag_name": tag_name,
            "assets": [{
                "id": 123,
                "name": "bootstrap-aarch64.zip",
                "state": "uploaded",
                "size": 42,
                "digest": f"sha256:{digest}",
            }],
        }), encoding="utf-8")
        tag_json = self.root / "tag.json"
        tag_json.write_text(json.dumps({"object": {"type": "commit", "sha": COMMIT}}), encoding="utf-8")

        result = self.run_verifier(
            "release", "--lock", lock, "--release-json", release_json, "--tag-json", tag_json
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(123, json.loads(result.stdout)["asset_id"])

        invalid_cases = [
            ({**json.loads(release_json.read_text()), "immutable": False},
             json.loads(tag_json.read_text())),
            ({**json.loads(release_json.read_text()), "assets": []},
             json.loads(tag_json.read_text())),
            ({**json.loads(release_json.read_text()), "assets": [{
                **json.loads(release_json.read_text())["assets"][0],
                "size": 256 * 1024 * 1024 + 1,
            }]}, json.loads(tag_json.read_text())),
            (json.loads(release_json.read_text()),
             {"object": {"type": "commit", "sha": "c" * 40}}),
        ]
        for invalid_release, invalid_tag in invalid_cases:
            with self.subTest(release=invalid_release, tag=invalid_tag):
                release_json.write_text(json.dumps(invalid_release), encoding="utf-8")
                tag_json.write_text(json.dumps(invalid_tag), encoding="utf-8")
                rejected = self.run_verifier(
                    "release", "--lock", lock, "--release-json", release_json, "--tag-json", tag_json
                )
                self.assertNotEqual(0, rejected.returncode)

    def test_accepts_arm64_apk_with_exact_embedded_bootstrap(self):
        bootstrap = self.write_bootstrap()
        bootstrap_bytes = bootstrap.read_bytes()
        lock = self.write_lock(hashlib.sha256(bootstrap_bytes).hexdigest())
        elf_header = bytearray(20)
        elf_header[:6] = b"\x7fELF\x02\x01"
        elf_header[18:20] = struct.pack("<H", 183)
        apk = self.root / "app.apk"
        with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as output:
            output.writestr("lib/arm64-v8a/libtermux-bootstrap.so", bytes(elf_header) + bootstrap_bytes)
        manifest = self.root / "AndroidManifest.xml"
        manifest.write_text(f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.prodysor.term">
            <permission android:name="com.prodysor.term.permission.RUN_COMMAND" />
            <application android:name="com.termux.app.TermuxApplication">
                <meta-data android:name="com.prodysor.term.bootstrap.SHA256"
                    android:value="{hashlib.sha256(bootstrap_bytes).hexdigest()}" />
                <provider android:authorities="com.prodysor.term.files" />
                <receiver android:name="com.termux.app.TermuxOpenReceiver" />
                <service android:name="com.termux.app.TermuxService" />
                <service android:name="com.termux.app.RunCommandService"
                    android:permission="com.prodysor.term.permission.RUN_COMMAND">
                    <intent-filter>
                        <action android:name="com.prodysor.term.RUN_COMMAND" />
                    </intent-filter>
                </service>
            </application>
        </manifest>''', encoding="utf-8")

        result = self.run_verifier(
            "apk", "--lock", lock, "--bootstrap", bootstrap, "--apk", apk,
            "--manifest-xml", manifest
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(hashlib.sha256(apk.read_bytes()).hexdigest(), json.loads(result.stdout)["apk_sha256"])

        valid_manifest = manifest.read_text()
        unsafe_manifests = [
            valid_manifest.replace(
                'package="com.prodysor.term"',
                'package="com.prodysor.term" android:sharedUserId="com.prodysor.term"',
            ),
            valid_manifest.replace(
                'android:name="com.termux.app.TermuxService"',
                'android:name="com.prodysor.term.app.TermuxService"',
            ),
        ]
        for unsafe_manifest in unsafe_manifests:
            with self.subTest(manifest=unsafe_manifest):
                manifest.write_text(unsafe_manifest, encoding="utf-8")
                rejected = self.run_verifier(
                    "apk", "--lock", lock, "--bootstrap", bootstrap, "--apk", apk,
                    "--manifest-xml", manifest
                )
                self.assertNotEqual(0, rejected.returncode)


if __name__ == "__main__":
    unittest.main()
