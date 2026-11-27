"""Check the native launcher opens and hands over the exact private profile fd."""

import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from oc_google.native_artifacts import StagedNativeBuild
from oc_google.native_namespace import (
    NativeNamespaceError, _OPEN_REPLICA, _REPLICA_FD, prepare_cold_namespace, public_certificate,
)


class NativeNamespaceTest(unittest.TestCase):
    certificate = b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"

    def test_public_certificate_rejects_a_combined_key_bundle(self):
        with TemporaryDirectory() as temporary:
            pem = Path(temporary) / "combined.pem"
            pem.write_bytes(self.certificate + b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")
            with self.assertRaisesRegex(NativeNamespaceError, "certificate-only PEM"):
                public_certificate(pem)

    def test_cold_mount_requires_the_pinned_profile_and_uses_bind_fd(self):
        with TemporaryDirectory() as temporary, socket.socket(socket.AF_UNIX) as listener:
            root = Path(temporary)
            native, profile = root / "native", root / "profile"
            native.mkdir(mode=0o700)
            profile.mkdir(mode=0o700)
            cert = root / "ca.pem"
            cert.touch(mode=0o600)
            cert.write_bytes(self.certificate)
            connector = root / "metadata.sock"
            listener.bind(str(connector))
            build = StagedNativeBuild(native / "agy_acp_server.par", "fixture")
            fd = os.open(profile, os.O_RDONLY | os.O_DIRECTORY)
            try:
                info = os.fstat(fd)
                source = Path(f"/proc/{os.getpid()}/fd/{fd}")
                with self.assertRaisesRegex(NativeNamespaceError, "pinned profile"):
                    prepare_cold_namespace(root, build, profile=profile, connector=connector, ca=cert,
                                           mount_source=(source, info.st_dev, info.st_ino + 1))
                (root / "etc").rename(root / "unused-etc")
                (root / "work").rename(root / "unused-work")
                launch = prepare_cold_namespace(root, build, profile=profile, connector=connector, ca=cert,
                                               mount_source=(source, info.st_dev, info.st_ino))
                position = launch.argv.index("--bind-fd")
                self.assertEqual(launch.argv[position + 1], _REPLICA_FD)
                self.assertNotIn(str(profile), launch.argv)
                self.assertNotIn(str(cert), launch.argv)
                self.assertEqual((root / "native-public-ca.pem").read_bytes(), self.certificate)
            finally:
                os.close(fd)

    def test_bootstrap_rejects_wrong_identity_or_mode_before_exec(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            info = root.stat()
            child = "import os,sys; print(os.fstat(int(sys.argv[1])).st_ino)"

            def run(inode):
                return subprocess.run([sys.executable, "-IBS", "-c", _OPEN_REPLICA, str(root), str(info.st_dev),
                                       str(inode), sys.executable, "-IBS", "-c", child, _REPLICA_FD],
                                      capture_output=True, text=True, timeout=2)

            self.assertEqual(run(info.st_ino).stdout.strip(), str(info.st_ino))
            self.assertEqual(run(info.st_ino + 1).returncode, 1)
            root.chmod(0o750)
            self.assertEqual(run(info.st_ino).returncode, 1)
