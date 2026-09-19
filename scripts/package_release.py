#!/usr/bin/env python3
"""Create a Windows release folder for the Luminator MTU to IPS Converter.

Build with a Python installation whose architecture matches the target
machine's Jet/DAO installation. DAO itself is a registered Windows COM server
and must be supplied by Luminator IPS or a compatible Microsoft runtime.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_NAME = "Luminator-MTU-to-IPS"
ENTRY_POINT = ROOT / "MTU_to_IPS_GUI.pyw"
REQUIRED_SOURCES = (
    ROOT / "build_ips_windows.py",
    ROOT / "mtu_reverse.py",
    ROOT / "PROBE_DAO.vbs",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--clean",
        action="store_true",
        help="remove prior PyInstaller build, dist, and spec outputs before building",
    )
    parser.add_argument(
        "--with-donor",
        action="store_true",
        help="include Donor.ips in the release folder; confirm redistribution is permitted first",
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="verify the expected executable and bundled PyInstaller runtime exist",
    )
    return parser.parse_args()


def ensure_sources(include_donor: bool) -> None:
    missing = [path for path in (ENTRY_POINT, *REQUIRED_SOURCES) if not path.is_file()]
    if include_donor and not (ROOT / "Donor.ips").is_file():
        missing.append(ROOT / "Donor.ips")
    if missing:
        joined = "\n".join(f"  {path}" for path in missing)
        raise SystemExit(f"Required source files are missing:\n{joined}")


def main() -> int:
    args = parse_args()
    ensure_sources(args.with_donor)

    build_dir = ROOT / "build" / "pyinstaller"
    dist_dir = ROOT / "dist"
    spec_dir = ROOT / "build" / "spec"
    release_dir = dist_dir / APP_NAME

    if args.clean:
        for path in (build_dir, release_dir, spec_dir / f"{APP_NAME}.spec"):
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--windowed",
        "--name",
        APP_NAME,
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(build_dir),
        "--specpath",
        str(spec_dir),
        "--collect-submodules",
        "win32com",
        "--hidden-import",
        "pythoncom",
        "--hidden-import",
        "pywintypes",
        "--add-data",
        f"{ROOT / 'PROBE_DAO.vbs'};.",
    ]
    if args.with_donor:
        command.extend(("--add-data", f"{ROOT / 'Donor.ips'};."))
    command.append(str(ENTRY_POINT))

    print("Building with:", sys.executable)
    subprocess.run(command, cwd=ROOT, check=True)

    executable = release_dir / f"{APP_NAME}.exe"
    if not executable.is_file():
        raise SystemExit(f"PyInstaller did not create the expected executable: {executable}")

    if args.smoke_test:
        runtime_dir = release_dir / "_internal"
        if not runtime_dir.is_dir():
            raise SystemExit(f"PyInstaller runtime directory is missing: {runtime_dir}")
        if not any(runtime_dir.glob("python*.dll")):
            raise SystemExit("PyInstaller runtime is missing its Python DLL.")
        print("Release layout smoke test passed.")

    print(f"Release folder: {release_dir}")
    print("Install matching-bit Windows Jet/DAO on the target PC before running the executable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())