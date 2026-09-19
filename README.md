# Luminator MTU to IPS Converter

A Windows recovery tool that reconstructs an editable Luminator IPS project (`.ips`) from a compiled MTU (`.mtu`).

> **Status:** reverse-engineered, field-tested with Luminator IPS V3.8, and still evolving. Always keep the original MTU and inspect the recovered project in IPS.

## What it recovers

The converter reconstructs the runtime-visible project data contained in an MTU, including:

- physical and logical signs
- sign targeting and selector masks
- message codes and frame structure
- text, positions, timing and effects
- compiled fonts and graphics
- RGB color planes and IPS color zones
- legacy Class-C projects: `Route / Destination / SmallSide`
- expanded Class-C projects: `Route / DestinationTop / DestinationBot / DestinationSide / RouteSide`
- the original MTU embedded back into `SignSetOutput`

The output database is written through Microsoft Jet/DAO so it can be opened and edited by Luminator IPS. The desktop converter has a determinate progress display for decode, validation, database writing, and post-write verification.

## Requirements

- Windows
- Microsoft Jet/DAO capable of opening the Luminator donor database
- Python 3.10+ if running from source
- `pywin32`

Double-click `SETUP_AND_RUN.cmd` to start the desktop converter. It probes 32-bit and 64-bit Jet/DAO, selects a compatible Python, installs `pywin32` when needed, verifies that DAO can be opened, and then starts the GUI. Legacy Luminator IPS installations commonly expose 32-bit Jet/DAO; use `SETUP_AND_RUN_32BIT.cmd` only when you need to force the known 32-bit runtime.

## Command line

```bat
py build_ips_windows.py input.mtu Donor.ips recovered.ips --name RECOVERED --class-c-profile auto
```

Preflight without writing a database:

```bat
py build_ips_windows.py input.mtu Donor.ips unused.ips --preflight-only --class-c-profile auto
```

Class-C options:

```text
auto
legacy
expanded
```

## Verification

After conversion, the tool writes:

```text
recovered.ips
recovered.ips.verify.json
```

The verification report checks database row counts and confirms that `SignSetOutput` contains the exact input MTU bytes.

Preflight parses and validates an MTU without opening DAO or writing an IPS. It reports unsupported message controls, selector problems, invalid sign geometry, and unresolved resource references before conversion begins.

## Recovery boundary

An MTU is a compiled runtime representation, not a perfect archival copy of every editor decision. Runtime display content can be recovered much more reliably than source-only organizational metadata.

Known examples of authoring information that may be altered or absent after compilation include:

- redundant blank editor rows
- source phrases clipped or normalized by the compiler
- legacy listing wording that differs from the actual sign text
- source timing values superseded by explicit compiled timing
- element splits that the compiler concatenated

The converter keeps reconstructed `MessageFrames` as the authoritative runtime representation and avoids presenting uncertain source-only distinctions as exact.

Unknown MTU variants may expose unsupported selectors, controls, sign hardware, or resource encodings. The preflight report preserves those details so the decoder can be extended from evidence rather than producing a project with silently misrouted or altered messages.