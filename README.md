# Luminator MTU to IPS Converter

A Windows recovery tool that reconstructs an editable Luminator IPS project (`.ips`) from a compiled MTU (`.mtu`).

> **Status:** reverse-engineered, field-tested with Luminator IPS V3.8, and still evolving. Always keep the original MTU and inspect the recovered project in IPS.

## What It Recovers

The converter reconstructs the runtime-visible project data contained in an MTU, including:

- physical and logical signs
- sign targeting and selector masks
- message codes and frame structure
- text, positions, timing and effects
- compiled fonts and graphics
- RGB color planes and IPS color zones
- Class C (destination) authoring elements chosen by you — see [Class C elements](#class-c-elements)
- the original MTU embedded back into `SignSetOutput`

The output database is written through Microsoft Jet/DAO so it can be opened and edited by Luminator IPS. The converter has a determinate progress display for decode, validation, database writing, and post-write verification.

## Requirements

- Windows
- Microsoft Jet/DAO capable of opening the Luminator donor database
- Python 3.10+ if running from source
- `pywin32`

Double-click `SETUP_AND_RUN.cmd` to start the desktop converter. It probes 32-bit and 64-bit Jet/DAO, selects a compatible Python, installs `pywin32` when needed, verifies that DAO can be opened, and then starts the GUI. Legacy Luminator IPS installations commonly expose 32-bit Jet/DAO; use `SETUP_AND_RUN_32BIT.cmd` only when you need to force the known 32-bit runtime.

## Command Line

```bat
py build_ips_windows.py input.mtu Donor.ips recovered.ips --name RECOVERED
```

Choose the Class C elements explicitly (otherwise they are suggested from the MTU):

```bat
py build_ips_windows.py input.mtu Donor.ips recovered.ips --class-c-elements RouteFront,MainFront,SecondaryFront,MainSide
```

Preflight without writing a database:

```bat
py build_ips_windows.py input.mtu Donor.ips unused.ips --preflight-only
```

For anomalous compiled data, explicitly enable best-effort recovery:

```bat
py build_ips_windows.py input.mtu Donor.ips recovered.ips --best-effort
```

The GUI provides the same option as **Best-effort anomaly recovery**, off by default.
It also applies to preflight (`--preflight-only --best-effort`).

## Class C Elements

Element names, listing columns and each frame's element binding are authoring metadata that IPS discards when compiling, so they are not stored in the MTU. You choose which elements the recovered project has; the GUI shows them as checkboxes and **Suggest from MTU** pre-selects the ones the messages need.

| Element | Meaning |
|---|---|
| `RouteFront` | route number on the front-family signs (front, Titan, ODK) |
| `MainFront` | main destination (always present; replaces `Destination` / `DestinationTop`) |
| `SecondaryFront` | lower destination line in a different font (replaces `DestinationBot`) |
| `RouteSide` | route number on the side signs |
| `MainSide` | side destination (replaces `DestinationSide` / `SmallSide`) |
| `RouteRear` | what the rear/route displays show |

Sign roles come from display geometry, so 08Bx and 04xx sign families and multi-vehicle MTUs are handled: displays up to 48 dots wide are rear/route displays, displays up to 8 dots tall are sides, and the rest are fronts.

A checked side or rear element is always filled from its signs, even when they show the same text as the front. Unchecked elements fold into their parent: `RouteSide`/`RouteRear` → `RouteFront`, `MainSide`/`SecondaryFront` → `MainFront`, and `RouteFront` → `MainFront`. **Suggest from MTU** only checks side and rear elements when those signs show something different from the front in some messages.

Listing text follows IPS conventions: `^` separates frames and `÷` separates lines within a frame. Compiled `MessageFrames` remain authoritative; the element choice only affects how messages are organized for editing in IPS.

## Verification

After conversion, the tool writes:

```text
recovered.ips
recovered.ips.verify.json
```

The verification report checks database row counts and confirms that `SignSetOutput` contains the exact input MTU bytes.

Preflight parses and validates an MTU without opening DAO or writing an IPS. It reports unsupported message controls, selector problems, invalid sign geometry, and unresolved resource references before conversion begins.

## Recovery Boundary

An MTU is a compiled runtime representation, not a perfect archival copy of every editor decision. Runtime display content can be recovered much more reliably than source-only organizational metadata.

Known examples of authoring information that may be altered or absent after compilation include:

- redundant blank editor rows
- source phrases clipped or normalized by the compiler
- legacy listing wording that differs from the actual sign text
- source timing values superseded by explicit compiled timing
- element splits that the compiler concatenated

The converter keeps reconstructed `MessageFrames` as the authoritative runtime representation and avoids presenting uncertain source-only distinctions as exact.

Unknown MTU variants may expose unsupported selectors, controls, sign hardware, or resource encodings. The preflight report preserves those details so the decoder can be extended from evidence rather than producing a project with silently misrouted or altered messages.