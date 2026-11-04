import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

SDK_ROOT = pathlib.Path(__file__).resolve().parent.parent


class WheelContentsTests(unittest.TestCase):
    """The published wheel holds the microvm package and nothing else.

    0.8.1 and earlier also installed tests/ and examples/ as top-level
    packages, where they could shadow a user's own "tests" package.
    """

    def build_wheel(self):
        try:
            import setuptools  # noqa: F401
            import wheel  # noqa: F401
        except ImportError as err:
            self.skipTest(f"building a wheel needs setuptools and wheel: {err}")
        work = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, ignore_errors=True)
        # Build from a copy so the build leaves no build/ or egg-info in the
        # source tree.
        src = work / "src"
        shutil.copytree(
            SDK_ROOT,
            src,
            ignore=shutil.ignore_patterns(
                "build", "dist", "*.egg-info", "__pycache__", ".venv*"
            ),
        )
        out = work / "dist"
        script = (
            "import sys\n"
            "from setuptools import build_meta\n"
            "print(build_meta.build_wheel(sys.argv[1]))\n"
        )
        done = subprocess.run(
            [sys.executable, "-c", script, str(out)],
            cwd=src,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        if done.returncode != 0:
            self.fail(f"wheel build failed:\n{done.stdout}\n{done.stderr}")
        return out / done.stdout.strip().splitlines()[-1]

    def test_wheel_holds_only_the_microvm_package(self):
        with zipfile.ZipFile(self.build_wheel()) as whl:
            names = whl.namelist()
        top = {name.split("/", 1)[0] for name in names}
        top = {t for t in top if not t.endswith(".dist-info")}
        self.assertEqual(top, {"microvm"}, f"unexpected top-level entries: {sorted(top)}")
        # The include pattern must keep the subpackages, not just microvm/.
        for module in (
            "microvm/__init__.py",
            "microvm/client.py",
            "microvm/image.py",
            "microvm/types.py",
            "microvm/_internal/api/v1/paths.py",
        ):
            self.assertIn(module, names)


if __name__ == "__main__":
    unittest.main()
