#!/usr/bin/env python3
"""Build a Windows EXE release folder with PyInstaller and Donor.ips."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DONOR_FILE = ROOT / "Donor.ips"
ENTRY_POINT = ROOT / "MTU_to_IPS_GUI.pyw"
DEFAULT_NAME = "LuminatorMTUtoIPS"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, default=ROOT / "dist")
    ap.add_argument("--name", default=DEFAULT_NAME, help="EXE and release-folder name")
    args = ap.parse_args()

    if not DONOR_FILE.is_file():
        raise SystemExit(f"Release donor not found: {DONOR_FILE}")
    if not ENTRY_POINT.is_file():
        raise SystemExit(f"GUI entry point not found: {ENTRY_POINT}")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    release_dir = output / args.name
    if release_dir.exists():
        shutil.rmtree(release_dir)

    with tempfile.TemporaryDirectory(prefix="luminator-pyinstaller-") as temporary:
        temp = Path(temporary)
        command = [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--windowed",
            "--onedir",
            "--name",
            args.name,
            "--distpath",
            str(output),
            "--workpath",
            str(temp / "work"),
            "--specpath",
            str(temp / "spec"),
            "--add-data",
            f"{DONOR_FILE}{';' if sys.platform == 'win32' else ':'}.",
            "--hidden-import",
            "pythoncom",
            "--hidden-import",
            "pywintypes",
            "--hidden-import",
            "win32com.client",
            "--collect-submodules",
            "win32com",
            str(ENTRY_POINT),
        ]
        try:
            subprocess.run(command, check=True, cwd=ROOT)
        except FileNotFoundError as exc:
            raise SystemExit("Python could not start PyInstaller.") from exc
        except subprocess.CalledProcessError as exc:
            raise SystemExit(f"PyInstaller build failed with exit code {exc.returncode}.") from exc

    donor = release_dir / "Donor.ips"
    executable = release_dir / f"{args.name}.exe"
    if not executable.is_file() or not donor.is_file():
        raise SystemExit("PyInstaller did not produce the EXE release and Donor.ips.")
    print(release_dir)


if __name__ == "__main__":
    main()
