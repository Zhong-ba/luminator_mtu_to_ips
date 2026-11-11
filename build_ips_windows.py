#!/usr/bin/env python3
"""Build an editable Luminator IPS .ips database from a compiled .mtu.

Windows writer paired with mtu_reverse.py.  Class C authoring elements
(RouteFront, MainFront, SecondaryFront, RouteSide, MainSide, RouteRear) are
chosen by the user or suggested from the MTU; see class_c_elements.py.  Parsing/reconstruction is
platform-independent; writing the old Microsoft Jet database is deliberately
performed through Microsoft's DAO engine on Windows instead of manufacturing
Jet pages by hand.

Requirements on the Windows machine:
  * Luminator IPS / a Jet-capable Microsoft runtime
  * Python (32-bit is safest with legacy Jet/DAO)
  * pywin32:  py -m pip install pywin32

Usage:
    py build_ips_windows.py input.mtu recovered.ips --name RECOVERED

The bundled Donor.ips (a plain Jet 3 IPS database with the built-in resource
libraries and controller modules but no project rows) is used automatically;
--donor selects another one.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import class_c_elements as cce
import mtu_reverse as mr

DONOR_FILENAME = "Donor.ips"


def bundled_donor() -> Path | None:
    """Locate the bundled donor: PyInstaller data dir, executable dir, then source dir."""
    candidates = []
    if getattr(sys, "_MEIPASS", None):
        candidates.append(Path(sys._MEIPASS) / DONOR_FILENAME)
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / DONOR_FILENAME)
    candidates.append(HERE / DONOR_FILENAME)
    return next((path for path in candidates if path.is_file()), None)


def _load_module_signature(blob: bytes) -> str | None:
    if len(blob) < 512:
        return None
    normalized = bytearray(blob)
    # Compilation patches payload length/check fields and the packed output version.
    normalized[4:10] = bytes(6)
    normalized[508:510] = bytes(2)
    return hashlib.sha256(normalized).hexdigest()


def compilation_metadata(mtu: mr.MTU) -> dict:
    module = mtu.data[:mtu.master_offset]
    packed = module[508:510] if len(module) >= 512 else b""
    digits = [digit for byte in packed for digit in (byte >> 4, byte & 15)]
    version = None
    warnings = []
    if len(digits) == 4 and all(digit < 10 for digit in digits):
        version = 0
        for digit in digits:
            version = version * 10 + digit
    else:
        warnings.append(
            f"Compiled output version is unavailable or not packed decimal "
            f"({packed.hex(' ') or 'missing header'}); using the native IPS default "
            "version 0, not an inferred source version.")
    return {
        "load_module_length": len(module),
        "load_module_sha256": hashlib.sha256(module).hexdigest(),
        "load_module_signature": _load_module_signature(module),
        "output_version_raw_hex": packed.hex(" "),
        "output_version": version,
        "warnings": warnings,
    }


def donor_load_module_binding(db, metadata: dict) -> dict:
    signature = metadata["load_module_signature"]
    if signature is None:
        raise RuntimeError("Cannot identify the embedded load module: its header is incomplete.")
    rs = db.OpenRecordset("SELECT * FROM [LoadModules] ORDER BY [LoadModID]", 4)
    try:
        while not rs.EOF:
            blob = bytes(rs.Fields("LOD").Value or b"")
            if _load_module_signature(blob) == signature:
                return {
                    "load_mod_id": int(rs.Fields("LoadModID").Value),
                    "description": str(rs.Fields("LMDescription").Value or ""),
                    "donor_sha256": hashlib.sha256(blob).hexdigest(),
                    "signature": signature,
                    "source": "donor",
                }
            rs.MoveNext()
    finally:
        rs.Close()
    raise RuntimeError(
        "No compatible load module was found in the donor. The embedded module "
        f"contains {metadata['load_module_length']} bytes "
        f"(signature {signature}).")


def ips_reference_databases(donor_path: Path) -> list[Path]:
    """Other IPS databases to consult: beside the donor and the installed IPS."""
    installed = Path(os.environ.get("SystemDrive", "C:") + "\\") / "Luminator" / "IPS"
    candidates = [donor_path.parent / "IPS.ips", donor_path.parent / "IPS.mdb",
                  installed / "IPS.ips", installed / "IPS.mdb"]
    result, seen = [], {donor_path.resolve()}
    for path in candidates:
        resolved = path.resolve()
        if resolved not in seen and path.is_file():
            seen.add(resolved)
            result.append(resolved)
    return result


def find_load_module(engine, paths: list[Path], signature: str) -> tuple[Path, str, bytes] | None:
    """Look for a stored controller module with the MTU's signature."""
    for path in paths:
        try:
            other = engine.OpenDatabase(str(path), False, True)
        except Exception:
            continue
        try:
            rs = other.OpenRecordset("SELECT LMDescription, LOD FROM [LoadModules]", 4)
            try:
                while not rs.EOF:
                    blob = bytes(rs.Fields("LOD").Value or b"")
                    if _load_module_signature(blob) == signature:
                        return path, str(rs.Fields("LMDescription").Value or ""), blob
                    rs.MoveNext()
            finally:
                rs.Close()
        except Exception:
            pass
        finally:
            other.Close()
    return None


def rebuilt_load_module(raw_mtu: bytes, mtu: mr.MTU) -> bytes:
    """Recover the controller module from the copy every MTU starts with.

    The compiler copies the module verbatim and patches only bytes 4-9 (payload
    word count and checksum) and 508-509 (output version), which it rewrites on
    every compile.  The count/checksum field is cleared; the version is kept.
    """
    module = bytearray(raw_mtu[:mtu.master_offset])
    module[4:10] = bytes(6)
    return bytes(module)


def probe_load_module(engine, db, donor_path: Path, metadata: dict) -> dict:
    """Report where ensure_load_module would take the module from, without writing."""
    try:
        return donor_load_module_binding(db, metadata)
    except RuntimeError:
        if metadata["load_module_signature"] is None:
            raise
    found = find_load_module(engine, ips_reference_databases(donor_path), metadata["load_module_signature"])
    if found is not None:
        return {"description": found[1], "signature": metadata["load_module_signature"],
                "source": f"copied from {found[0]}"}
    return {"description": f"(Recovered-{metadata['load_module_signature'][:8]}.lod)",
            "signature": metadata["load_module_signature"], "source": "rebuilt from the MTU"}


def ensure_load_module(engine, db, donor_path: Path, model: dict, pythoncom=None, VARIANT=None) -> dict:
    """Bind the MTU's controller module, adding it to the output database if needed.

    Order: the donor, then other local IPS databases (copied in), then the copy
    embedded in the MTU itself.  A different module is never substituted.
    """
    metadata = model["compilation_metadata"]
    try:
        return donor_load_module_binding(db, metadata)
    except RuntimeError:
        if metadata["load_module_signature"] is None:
            raise
    found = find_load_module(engine, ips_reference_databases(donor_path), metadata["load_module_signature"])
    if found is not None:
        path, description, blob = found
        source = f"copied from {path}"
    else:
        blob = rebuilt_load_module(model["raw_mtu"], model["mtu"])
        description = f"(Recovered-{metadata['load_module_signature'][:8]}.lod)"
        source = "rebuilt from the MTU"
    rs = db.OpenRecordset("LoadModules", 2)
    try:
        rs.AddNew()
        rs.Fields("LMDescription").Value = description[:80]
        rs.Fields("LOD").AppendChunk(VARIANT(pythoncom.VT_ARRAY | pythoncom.VT_UI1, list(blob)))
        rs.Update()
        rs.Bookmark = rs.LastModified
        load_mod_id = int(rs.Fields("LoadModID").Value)
    finally:
        rs.Close()
    return {
        "load_mod_id": load_mod_id, "description": description,
        "donor_sha256": hashlib.sha256(blob).hexdigest(),
        "signature": metadata["load_module_signature"], "source": source,
    }


def build_model(mtu_path: Path, class_c_layout: cce.ClassCLayout | cce.CustomLayout | None = None,
                best_effort: bool = False) -> dict:
    """Decode an MTU.  ``class_c_layout=None`` suggests elements from the MTU."""
    raw = mtu_path.read_bytes()
    mtu = mr.MTU(raw)

    fheaders, _ = mr.parse_pointer_resources(
        mtu.section_data(2), mtu.sections[2].offset, mtu.load_base, "font")
    gheaders, _ = mr.parse_pointer_resources(
        mtu.section_data(3), mtu.sections[3].offset, mtu.load_base, "graphic")

    sign_tables = mr.reconstruct_sign_tables(mtu)
    address_to_lsign = {int(x["PSignAddr"]): int(x["LSignID"]) for x in sign_tables["LogicalSignBuild"]}
    banks = {}
    for bidx, letter in enumerate("ABCDEFGHIJK", start=5):
        sec = mtu.sections[bidx]
        banks[letter] = {
            "records": mr.split_message_bank(mtu.section_data(bidx), sec.offset, address_to_lsign)
        }

    font_metrics = mr.build_font_metrics(raw, fheaders, mtu.sections[3].offset)
    graphic_metrics = mr.build_graphic_metrics(raw, gheaders, mtu.sections[4].offset)
    runtime_frames = mr.reconstruct_messageframes(
        banks, font_metrics, sign_tables, graphic_metrics, best_effort=best_effort)
    runtime_frames = mr.assign_color_frame_numbers(runtime_frames)
    runtime_frames = mr.collapse_compiler_rgb_placeholders(runtime_frames)
    color_zones = mr.reconstruct_color_zones(runtime_frames, sign_tables)
    frames = mr.collapse_color_plane_frames(runtime_frames)
    resources = mr.reconstruct_resource_tables(
        raw, mtu, fheaders, gheaders, frames, sign_tables)
    zones = mr.reconstruct_effect_zones(frames, sign_tables)
    if class_c_layout is None:
        class_c_layout = cce.suggest_layout(frames, sign_tables)
    class_c = cce.decode_class_c(frames, sign_tables, class_c_layout)
    db_frames = mr.database_ready_messageframes(
        frames, resources, {ordinal: class_c.element_id(ordinal) for ordinal in class_c.element_of})

    return {
        "raw_mtu": raw,
        "mtu": mtu,
        "banks": banks,
        "sign_tables": sign_tables,
        "frames": frames,
        "runtime_frames": runtime_frames,
        "resources": resources,
        "effect_zones": zones,
        "color_zones": color_zones,
        "db_frames": db_frames,
        "class_c_layout": class_c_layout,
        "class_c": class_c,
        "best_effort": best_effort,
        "compilation_metadata": compilation_metadata(mtu),
    }


def identify_unknown_message_tokens(model: dict, example_limit: int = 5) -> list[dict]:
    """Catalog unresolved message bytes and controls with useful raw context."""
    catalog = {}
    for bank_name, bank in model.get("banks", {}).items():
        for record in bank.get("records", []):
            for segment in record.get("segments", []):
                for token in segment.get("controls", []):
                    if token.get("kind") == "control" and token.get("semantic") == "unresolved":
                        token_kind = "unresolved_control"
                        token_name = str(token.get("opcode", "unknown"))
                    elif token.get("kind") == "byte":
                        token_kind = "raw_byte"
                        token_name = f"0x{int(token.get('value', 0)):02X}"
                    else:
                        continue

                    key = (token_kind, token_name)
                    entry = catalog.setdefault(key, {
                        "kind": token_kind,
                        "token": token_name,
                        "occurrences": 0,
                        "examples": [],
                    })
                    entry["occurrences"] += 1
                    if len(entry["examples"]) >= example_limit:
                        continue

                    body = bytes.fromhex(segment.get("body_hex", ""))
                    offset = int(token.get("offset", 0))
                    context = body[max(0, offset - 12):offset + 13]
                    entry["examples"].append({
                        "bank": bank_name,
                        "message_code": int(record.get("msg_code", 0)),
                        "record_file_offset": f"0x{int(record.get('file_offset', 0)):X}",
                        "segment_index": int(segment.get("segment_index", 0)),
                        "body_offset": int(segment.get("body_offset", 0)),
                        "token_offset": offset,
                        "selector_hex": segment.get("selector", {}).get("raw_hex", ""),
                        "target_lsign_ids": list(segment.get("target_lsign_ids", [])),
                        "context_hex": context.hex(" "),
                    })
    return sorted(catalog.values(), key=lambda entry: (entry["kind"], entry["token"]))


def preflight_model(model: dict, known_font_ids: set[int] | None = None) -> dict:
    """Source-independent parser sanity checks before touching a Jet database."""
    errors=[]; warnings=[]; unresolved=[]; unknown_masks=[]; trailing_markers=[]
    warnings.extend(model.get("sign_catalog", {}).get("warnings", []))
    warnings.extend(model.get("compilation_metadata", {}).get("warnings", []))
    if model.get("load_module_error"):
        errors.append(model["load_module_error"])
    unknown_token_catalog = identify_unknown_message_tokens(model)
    segment_count=0; control_count=0
    message_records=0
    message_classes = {}
    best_effort = bool(model.get("best_effort", False))
    recovery_anomalies = []
    font_indexes = {int(font.get("CompiledFontIndex", index))
                    for index, font in enumerate(model["resources"]["Fonts"])}
    graphic_indexes = set(model["resources"].get("graphic_index_map", {}))
    if best_effort:
        warnings.append(
            "Best-effort anomaly recovery is enabled. Editable appearance is unverified; "
            "the original MTU bytes are retained unchanged. Review the recovery_anomalies report.")

    def record_anomaly(kind: str, token: dict, letter: str, record: dict,
                       segment: dict, action: str) -> None:
        body = bytes.fromhex(segment.get("body_hex", ""))
        offset = int(token.get("offset", 0))
        entry = {
            "kind": kind, "bank": letter, "message_code": int(record.get("msg_code", 0)),
            "record_file_offset": f"0x{int(record.get('file_offset', 0)):X}",
            "segment_index": int(segment.get("segment_index", 0)),
            "token_offset": offset, "decoded_token": dict(token),
            "selector_hex": segment.get("selector", {}).get("raw_hex", ""),
            "target_lsign_ids": list(segment.get("target_lsign_ids", [])),
            "physical_addresses": list(segment.get("selector", {}).get("physical_addresses", [])),
            "context_hex": body[max(0, offset - 12):offset + 13].hex(" "),
            "action": action if best_effort else f"blocked in strict mode; best-effort would {action}",
        }
        recovery_anomalies.append(entry)
        location = (f"{letter}{entry['message_code']} segment {entry['segment_index']} "
                    f"token +{offset} at record {entry['record_file_offset']}")
        if best_effort:
            warnings.append(f"{location}: {kind}; {action}. Appearance is unverified.")
        elif kind == "invalid_font_selector":
            errors.append(f"{location}: unknown compiled font index {token['font_index']}")

    for letter, bank in model["banks"].items():
        records = len(bank.get("records", []))
        if letter in "ABCDEFGHIJK" and records:
            message_classes[letter] = records
        message_records += records
        for rec in bank.get("records",[]):
            for seg in rec.get("segments",[]):
                segment_count += 1
                unknown_masks.extend(seg.get("selector",{}).get("unknown_masks",[]))
                if not seg.get("target_lsign_ids"):
                    selector = seg.get("selector",{})
                    unconfigured = selector.get("unconfigured_addresses",[])
                    if selector.get("empty_placeholder"):
                        continue
                    if unconfigured:
                        warnings.append(
                            f"segment at 0x{rec.get('file_offset',0):X} targets only unconfigured physical addresses: {unconfigured}")
                    else:
                        errors.append(f"segment at 0x{rec.get('file_offset',0):X} has no logical-sign target")
                for tok in seg.get("controls",[]):
                    if tok.get("kind") == "control":
                        control_count += 1
                        if tok.get("semantic") == "font_selector" and tok["font_index"] not in font_indexes:
                            record_anomaly(
                                "invalid_font_selector", tok, letter, rec, seg,
                                "keep consumed parameter bytes out of text; character signs ignore "
                                "font changes and matrix signs retain the last valid/default font")
                        elif (tok.get("semantic") == "graphic_selector" and
                              tok["graphic_index"] not in graphic_indexes):
                            errors.append(
                                f"{letter}{rec.get('msg_code')} segment {seg.get('segment_index')}: "
                                f"unknown compiled graphic index {tok['graphic_index']}")
                        if tok.get("semantic") == "unresolved":
                            unresolved.append(tok.get("opcode"))
                            record_anomaly(
                                "unresolved_control", tok, letter, rec, seg,
                                "retain the original bytes; omit the unsupported rendering action")
                        elif tok.get("semantic") == "trailing_marker":
                            trailing_markers.append(
                                f"{letter} message {rec.get('msg_code')} segment "
                                f"{seg.get('segment_index')} at 0x{rec.get('file_offset',0):X}")
                    elif tok.get("kind") == "byte":
                        unresolved.append(f"byte_0x{int(tok.get('value',0)):02X}")
                        record_anomaly(
                            "raw_byte", tok, letter, rec, seg,
                            "retain the original byte as non-rendering data in the editable recovery")
    if unknown_masks:
        errors.append(f"unknown sign selector masks: {sorted(set(unknown_masks))}")
    if unresolved and not best_effort:
        errors.append(f"unresolved message controls: {dict(defaultdict(int)) if False else sorted(set(unresolved))}")
    if trailing_markers:
        warnings.append(
            "treated terminal 0x1E as a non-rendering marker in "
            + ", ".join(trailing_markers))
    if model["banks"] and not message_records:
        warnings.append(
            "MTU contains no compiled message records; no Class A-K messages can be recovered")

    lsign_ids={int(r["LSignID"]) for r in model["sign_tables"]["LogicalSigns"]}
    font_ids={int(r["FontID"]) for r in model["resources"]["Fonts"]}
    graph_ids={int(r["GraphicID"]) for r in model["resources"]["Graphics"]}
    known_font_ids = set(known_font_ids or ()) if known_font_ids is not None else None
    known_fonts = (len(font_ids & known_font_ids) if known_font_ids is not None else None)
    colored_graphics = sum(
        any(graphic.get(key) for key in ("RedGraphicBlobHex", "GreenGraphicBlobHex", "BlueGraphicBlobHex"))
        for graphic in model["resources"]["Graphics"]
    )
    for sign in model["sign_tables"]["LogicalSigns"]:
        if int(sign["LSignDotHeight"]) <= 0 or int(sign["LSignDotWidth"]) <= 0:
            errors.append(
                f"logical sign {sign['LSignID']} has invalid dimensions "
                f"{sign['LSignDotHeight']}x{sign['LSignDotWidth']}")
    for i, row in enumerate(model.get("frames", [])):
        if row.get("FontIndex") is not None and row["FontIndex"] not in font_indexes:
            errors.append(f"frame {i} references unknown compiled font index {row['FontIndex']}")
        if row.get("GraphicIndex") is not None and row["GraphicIndex"] not in graphic_indexes:
            errors.append(f"frame {i} references unknown compiled graphic index {row['GraphicIndex']}")
    for i,r in enumerate(model["db_frames"]):
        if int(r["LSignID"]) not in lsign_ids: errors.append(f"frame {i} references unknown LSignID {r['LSignID']}")
        if r.get("FontID") is not None and int(r["FontID"]) not in font_ids: errors.append(f"frame {i} references unknown FontID {r['FontID']}")
        if r.get("GraphicID") is not None and int(r["GraphicID"]) not in graph_ids: errors.append(f"frame {i} references unknown GraphicID {r['GraphicID']}")
        if r.get("GraphicID") is None and r.get("FontID") is None:
            errors.append(f"frame {i} (class {r['MsgClassID']} msg {r['MsgCode']} sign {r['LSignID']} "
                          f"frame {r['Frame']}) has neither FontID nor GraphicID; IPS compile would fail")
    group_keys={(int(r["MsgClassID"]),int(r["MsgCode"]),int(r["LSignID"]),int(r["Frame"])) for r in model["db_frames"]}
    zone_keys={(int(r["MsgClassID"]),int(r["MsgCode"]),int(r["LSignID"]),int(r["Frame"])) for r in model["effect_zones"]}
    if group_keys != zone_keys:
        errors.append(f"EffectZones/group mismatch: frames={len(group_keys)} zones={len(zone_keys)}")
    pairs={(int(r["MsgClassID"]),int(r["MsgCode"])) for r in model["db_frames"]}
    return {
        "status":"PASS" if not errors else "FAIL", "errors":errors, "warnings":warnings,
        "message_pairs":len(pairs), "frame_rows":len(model["db_frames"]),
        "sign_frame_groups":len(group_keys), "effect_zones":len(zone_keys),
        "logical_signs":len(lsign_ids), "fonts":len(font_ids), "graphics":len(graph_ids),
        "message_records":message_records, "segments":segment_count, "controls":control_count,
        "message_classes":message_classes,
        "font_categories": {
            "known": known_fonts,
            "unknown": len(font_ids) - known_fonts if known_fonts is not None else None,
        },
        "graphic_categories": {
            "colored": colored_graphics,
            "monochrome": len(graph_ids) - colored_graphics,
        },
        "unknown_selector_masks":sorted(set(unknown_masks)),
        "unresolved_controls":sorted(set(unresolved)),
        "unknown_token_catalog":unknown_token_catalog,
        "recovery_mode": "best_effort" if best_effort else "strict",
        "recovery_anomalies": recovery_anomalies,
        "mtu_sha256":hashlib.sha256(model["raw_mtu"]).hexdigest(),
        "class_c_layout": model["class_c_layout"].describe() if model.get("class_c_layout") else None,
        "class_c_element_usage": dict(model["class_c"].usage) if model.get("class_c") else {},
        "compilation_metadata": model.get("compilation_metadata"),
        "load_module_binding": model.get("load_module_binding"),
    }


def class_message_rows(model: dict) -> dict[str, list[dict]]:
    """Create minimal authoring/listing rows for IPS message-class tables.

    These columns are not sufficient to reproduce the full original author's
    Route/Destination field decomposition because compilation discards those
    labels.  MessageFrames remains authoritative for recovered display output.
    The generated summaries make every recovered MsgCode visible/editable in
    IPS's standard class A/B/C listings.
    """
    frames = model["frames"]
    by_msg = defaultdict(list)
    for r in frames:
        by_msg[(r["MsgClassID"], r["MsgCode"])].append(r)

    def frame_summary(rows: list[dict], preferred_lsign: int | None = None) -> str:
        use = rows
        if preferred_lsign is not None:
            preferred = [r for r in rows if r["LSignID"] == preferred_lsign and r.get("Phrase")]
            if preferred:
                use = preferred
        per_frame = defaultdict(list)
        seen = set()
        for r in use:
            text = r.get("Phrase") or ""
            if not text:
                continue
            k = (r["Frame"], text)
            if k in seen:
                continue
            seen.add(k)
            per_frame[r["Frame"]].append(text)
        parts = []
        for fr in sorted(per_frame):
            parts.append("".join(per_frame[fr]))
        return "^".join(parts)

    def front_destination_summary(rows: list[dict]) -> str:
        use=[r for r in rows if r["LSignID"]==2 and r.get("Phrase")] or [r for r in rows if r.get("Phrase")]
        per_frame=defaultdict(list)
        for r in use: per_frame[r["Frame"]].append(r.get("Phrase") or "")
        # When a compiled frame contains multiple authoring elements, prefer the
        # most descriptive/longest phrase for the class-list summary.
        return "^".join(max(v,key=len) for _,v in sorted(per_frame.items()) if v)

    def class_a_title_summary(rows: list[dict]) -> str:
        """Reassemble Class-A title fragments from one logical sign's frames."""
        text_rows = [r for r in rows if r.get("Phrase")]
        if not text_rows:
            return ""
        lsign_id = min(int(r["LSignID"]) for r in text_rows)
        text_rows = [r for r in text_rows if int(r["LSignID"]) == lsign_id]
        return "".join(
            str(r["Phrase"])
            for r in sorted(text_rows, key=lambda r: (
                int(r["Frame"]), int(r.get("YPos", 1)), int(r.get("XPos", 1))))
        )

    out = {"ClassAMsgs": [], "ClassBMsgs": [], "ClassCMsgs": []}
    class_c = model["class_c"]
    for (cls, code), rows in sorted(by_msg.items()):
        if cls == 1:
            out["ClassAMsgs"].append({
                "MsgCode": code, "MsgClassID": 1, "Approved": True,
                "Title": class_a_title_summary(rows)[:255], "IDTitle": 1,
                "Text": "", "IDText": 2,
            })
        elif cls == 2:
            out["ClassBMsgs"].append({
                "MsgCode": code, "MsgClassID": 2, "Approved": True,
                "PRText": frame_summary(rows)[:255], "IDPRText": 3,
                "PRBot": "", "IDPRBot": 18,
                "PRSide": "", "IDPRSide": 19,
            })
        elif cls == 3:
            row = {"MsgCode": code, "MsgClassID": 3, "Approved": True}
            listing = class_c.listings.get(int(code), {})
            for name in class_c.layout.elements:
                row[name] = listing.get(name, "")[:255]
                row["ID" + name] = class_c.layout.element_id(name)
            out["ClassCMsgs"].append(row)
    return out


SIGN_CATALOG_FIELDS = (
    "PSignPartNumber", "PSignName", "PSignDescription", "PSignType",
    "PSignDotHeight", "PSignDotWidth", "PSignCharHeight", "PSignCharWidth",
    "PSignCharLines", "PSignNumChars", "PSignDotColor",
)


def read_sign_catalog(db, source: str) -> list[dict]:
    rs = db.OpenRecordset(
        "SELECT " + ", ".join(f"[{field}]" for field in SIGN_CATALOG_FIELDS)
        + " FROM [PhysicalSigns]", 4)
    rows = []
    try:
        while not rs.EOF:
            row = {field: rs.Fields(field).Value for field in SIGN_CATALOG_FIELDS}
            row["source"] = source
            rows.append(row)
            rs.MoveNext()
    finally:
        rs.Close()
    return rows


def load_sign_catalog(engine, donor_db, donor_path: Path) -> tuple[list[dict], list[str]]:
    rows = []
    warnings = []
    for resolved in ips_reference_databases(donor_path):
        try:
            catalog_db = engine.OpenDatabase(str(resolved), False, True)
            try:
                rows.extend(read_sign_catalog(catalog_db, str(resolved)))
            finally:
                catalog_db.Close()
        except Exception as error:
            warnings.append(f"Could not read sign catalog {resolved}: {error}")
    rows.extend(read_sign_catalog(donor_db, str(donor_path.resolve())))
    return rows, warnings


def apply_sign_catalog(signs: dict, catalog: list[dict],
                       warnings: list[str] | None = None) -> dict:
    """Bind display metadata only; compiled geometry and runtime defaults win."""
    warnings = list(warnings or [])
    matches = {}
    for physical in signs["PhysicalSigns"]:
        part = str(physical["PSignPartNumber"]).strip().upper()
        kind = physical["PSignType"]
        geometry_fields = (
            ("PSignDotHeight", "PSignDotWidth") if kind == "Matrix" else
            ("PSignCharHeight", "PSignCharWidth", "PSignCharLines", "PSignNumChars"))
        match = next((
            row for row in catalog
            if str(row["PSignPartNumber"] or "").strip().upper() == part
            and row["PSignType"] == kind
            and all(row[field] == physical[field] for field in geometry_fields)
            and row["PSignName"] and row["PSignDotColor"] is not None
        ), None)
        if match is None:
            warnings.append(
                f"Address {physical['PSignAddr']} type {part}: no matching sign catalog "
                "entry for the compiled geometry; keeping synthetic names and fallback preview color.")
            continue
        physical.update({
            "PSignName": str(match["PSignName"]),
            "PSignDescription": str(match["PSignDescription"] or ""),
            "PSignDotColor": int(match["PSignDotColor"]),
            "name_origin": "native_catalog",
        })
        matches[physical["PSignID"]] = match

    physical_by_id = {row["PSignID"]: row for row in signs["PhysicalSigns"]}
    logical_by_id = {row["LSignID"]: row for row in signs["LogicalSigns"]}
    counts = Counter(str(row["PSignName"])[:20].casefold() for row in signs["PhysicalSigns"])
    used = set()
    for physical in signs["PhysicalSigns"]:
        base = str(physical["PSignName"])[:20]
        name = base
        if counts[base.casefold()] > 1:
            suffix = f"_A{physical['PSignAddr']}"
            name = base[:20 - len(suffix)] + suffix
        ordinal = 2
        while name.casefold() in used:
            suffix = f"_{ordinal}"
            name = base[:20 - len(suffix)] + suffix
            ordinal += 1
        used.add(name.casefold())
        physical["PSignName"] = name

    logical_used = {
        str(logical_by_id[link["LSignID"]]["LSignName"]).casefold()
        for link in signs["LogicalSignBuild"] if link["PSignID"] not in matches
    }
    bindings = []
    for link in signs["LogicalSignBuild"]:
        physical = physical_by_id[link["PSignID"]]
        logical = logical_by_id[link["LSignID"]]
        match = matches.get(link["PSignID"])
        if match is not None:
            name = physical["PSignName"]
            ordinal = 1
            while name.casefold() in logical_used:
                suffix = f"_A{link['PSignAddr']}" + (f"_{ordinal}" if ordinal > 1 else "")
                name = physical["PSignName"][:20 - len(suffix)] + suffix
                ordinal += 1
            logical_used.add(name.casefold())
            logical.update({
                "LSignName": name,
                "LSignDescription": physical["PSignDescription"],
                "name_origin": "native_catalog",
            })
        bindings.append({
            "address": link["PSignAddr"], "part": physical["PSignPartNumber"],
            "physical_name": physical["PSignName"], "logical_name": logical["LSignName"],
            "preview_color": physical.get("PSignDotColor", 33023),
            "source": match["source"] if match is not None else "synthetic",
        })
    return {"bindings": bindings, "warnings": warnings}


def enrich_physical_row(p: dict, default_font_names: dict[int, str] | None = None) -> dict:
    is_matrix = p["PSignType"] == "Matrix"
    default_font = (default_font_names or {}).get(
        int(p["DefaultFontIndex"]), mr.recovered_font_file_stem(int(p["DefaultFontIndex"])))
    return {
        "PSignID": p["PSignID"],
        "PSignName": p["PSignName"],
        "PSignDescription": p.get("PSignDescription", "Recovered from compiled MTU"),
        "PSignPartNumber": p["PSignPartNumber"],
        "PSignType": p["PSignType"], "PSignDotShape": "Round", "PSignDotAspect": "1/1",
        "PSignDotHeight": p["PSignDotHeight"], "PSignDotWidth": p["PSignDotWidth"],
        "PSignCharWidth": p["PSignCharWidth"], "PSignAllowMod": False,
        "PSignDotColor": p.get("PSignDotColor", 33023), "PSignCharLines": p["PSignCharLines"],
        "PSignNumChars": p["PSignNumChars"], "PSignCharHeight": p["PSignCharHeight"],
        "PSignLineTime": p["PSignLineTime"], "PSignBlankTime": p["PSignBlankTime"],
        "PSignBlankBeforePR": p["PSignBlankBeforePR"],
        "PSignBlankBeforeRPT": p["PSignBlankBeforeRPT"],
        "SuppressCentering": False, "DefAttr1": 0, "DefAttr2": 0,
        "Def1Color": 33023, "Def2Color": 0, "Reserve1": "0", "Reserve2": "0",
        "DefaultFont": default_font, "Emergency": p["Emergency"],
        "PSignDfltAddr": p["PSignAddr"],
        "ScrollCapable": is_matrix, "SparkleCapable": is_matrix,
        "AlertCapable": not is_matrix, "FormatCapable": False,
        "BlinkCapable": not is_matrix, "ScrollUpCapable": is_matrix,
        "ScrollDownCapable": is_matrix, "ScrollRightToLeftCapable": is_matrix,
        "ScrollSpeed1Capable": is_matrix, "ScrollSpeed2Capable": is_matrix,
        "ScrollSpeed3Capable": is_matrix, "WinScrollCapable": is_matrix,
    }


def require_windows_dao():
    if os.name != "nt":
        raise RuntimeError(
            "The MTU parser works on any OS, but final .ips writing requires Windows "
            "because IPS databases use a legacy Microsoft Jet format. Run this "
            "writer on a Windows installation that can run Luminator IPS.")
    try:
        import pythoncom
        import win32com.client as win32client
        Dispatch = win32client.Dispatch
        VARIANT = win32client.VARIANT
    except Exception as e:
        import traceback as _tb
        raise RuntimeError(
            "[PYWIN32_IMPORT_FAILED] pywin32 could not be loaded by this exact Python runtime.\n"
            f"Python: {sys.executable}\n"
            f"Details: {type(e).__name__}: {e}"
        ) from e
    return pythoncom, Dispatch, VARIANT


def is_database_in_use_error(error: object) -> bool:
    text = str(error).lower()
    return (
        "already opened exclusively" in text
        or "opened exclusively by user" in text
        or "5003356" in text
        or "-2146824932" in text
    )


def open_dao(path: Path, exclusive: bool = False):
    pythoncom, Dispatch, VARIANT = require_windows_dao()
    # The GUI performs conversions in a worker thread.  COM must be initialized
    # explicitly on that thread; importing pythoncom on the main thread is not enough.
    pythoncom.CoInitialize()
    import struct
    errors = []
    for progid in ("DAO.DBEngine.36", "DAO.DBEngine.35"):
        try:
            engine = Dispatch(progid)
            db = engine.OpenDatabase(str(path), exclusive, False)
            return pythoncom, VARIANT, engine, db
        except Exception as e:
            errors.append(f"{progid}: {type(e).__name__}: {e}")
    pythoncom.CoUninitialize()
    if any(is_database_in_use_error(error) for error in errors):
        raise RuntimeError(
            "[DATABASE_IN_USE] Jet/DAO started successfully, but the database is open exclusively "
            "in Luminator IPS or another Jet/DAO process. Close that program completely, then retry.\n"
            f"Database: {path}\n"
            + "\n".join(errors)
        )
    bits = struct.calcsize("P") * 8
    raise RuntimeError(
        "[DAO_OPEN_FAILED] Microsoft Jet/DAO could not be opened by this Python process.\n"
        f"Python: {sys.executable} ({bits}-bit)\n"
        + "\n".join(errors)
        + "\nIf Luminator IPS installed 32-bit Jet/DAO, use 32-bit Python. "
          "The v6.2 launcher probes DAO bitness and selects a matching Python automatically."
    )


def max_value(db, table: str, field: str) -> int:
    rs = db.OpenRecordset(f"SELECT Max([{field}]) AS M FROM [{table}]")
    try:
        v = rs.Fields("M").Value
        return int(v) if v is not None else 0
    finally:
        rs.Close()


def clear_table(db, table: str) -> None:
    db.Execute(f"DELETE FROM [{table}]")


def table_fields(db, table: str) -> set[str]:
    td = db.TableDefs(table)
    return {str(td.Fields(i).Name) for i in range(td.Fields.Count)}


def table_field_info(db, table: str) -> dict[str, tuple[int, int, bool, bool]]:
    """Return Jet field constraints used by the writer.

    Values are ``(DAO type, declared size, allow_zero_length, required)``.
    Jet distinguishes an empty text string from NULL.  Fields that disallow
    zero-length strings receive NULL for an unused value instead.
    """
    td = db.TableDefs(table)
    out = {}
    for i in range(td.Fields.Count):
        f = td.Fields(i)
        try:
            size = int(f.Size)
        except Exception:
            size = 0
        try:
            allow_zero = bool(f.AllowZeroLength)
        except Exception:
            # The property is meaningful for Text/Memo fields.  Defaulting to
            # True for other types prevents accidental coercion.
            allow_zero = True
        try:
            required = bool(f.Required)
        except Exception:
            required = False
        out[str(f.Name)] = (int(f.Type), size, allow_zero, required)
    return out


def _fit_field_value(value, info: tuple[int, int, bool, bool] | None):
    """Coerce a Python value to the live Jet field constraints.

    * Text is truncated to its declared maximum.
    * ``""`` becomes NULL when ``AllowZeroLength`` is false.  Native IPS
      Class C columns allow zero-length strings (see _ensure_class_c_fields).
    Binary/OLE values are never truncated here.
    """
    if value is None or info is None:
        return value
    dtype, size, allow_zero, required = info
    if dtype == 10 and isinstance(value, str):
        if value == "" and not allow_zero:
            if required:
                raise RuntimeError(
                    "Jet text field is Required and also disallows zero-length strings; "
                    "an empty reconstructed value cannot be represented safely"
                )
            return None
        if size > 0 and len(value) > size:
            return value[:size]
    return value


def append_rows(db, table: str, rows: list[dict], blob_fields: dict[str, str] | None = None,
                pythoncom=None, VARIANT=None, row_callback=None) -> None:
    if not rows:
        return
    blob_fields = blob_fields or {}
    fields = table_fields(db, table)
    field_info = table_field_info(db, table)
    rs = db.OpenRecordset(table, 2)  # dbOpenDynaset
    try:
        for ordinal, row in enumerate(rows, start=1):
            rs.AddNew()
            for key, value in row.items():
                target = blob_fields.get(key, key)
                if target not in fields:
                    continue
                if key in blob_fields:
                    if value is None:
                        continue
                    blob = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
                    variant = VARIANT(pythoncom.VT_ARRAY | pythoncom.VT_UI1, list(blob))
                    rs.Fields(blob_fields[key]).AppendChunk(variant)
                    continue
                if value is None:
                    continue
                fitted = _fit_field_value(value, field_info.get(target))
                if fitted is None:
                    # Leave a newly-added record field as Jet NULL.
                    continue
                try:
                    rs.Fields(target).Value = fitted
                except Exception as e:
                    raise RuntimeError(f"{table}.{target} rejected value {value!r}: {e}") from e
            try:
                rs.Update()
            except Exception as e:
                ident = {k: row.get(k) for k in ("MsgCode", "MsgClassID", "LSignID", "SignSetID") if k in row}
                raise RuntimeError(f"{table} failed to save row {ident or row}: {e}") from e
            if row_callback is not None:
                row_callback(table, ordinal, len(rows))
    finally:
        rs.Close()



def prepare_rows(model: dict, project_name: str,
                 default_font_names: dict[int, str] | None = None) -> dict:
    """Prepare database rows while keeping MTU-local IDs.

    Jet AutoNumber columns are deliberately left as local IDs at this stage.
    The writer skips those fields during insertion, reads back the AutoNumber
    assigned by DAO, then remaps dependent foreign keys.
    """
    signs = model["sign_tables"]
    resources = model["resources"]

    fonts=[]
    for r in resources["Fonts"]:
        fonts.append({
            "FontID":r["FontID"], "FontName":r["FontName"],
            "FontDescription":r["FontDescription"], "FontType":r["FontType"],
            "FontSize":r["FontSize"], "FontAllowMod":r["FontAllowMod"],
            "FontFile":r["FontFile"], "FontWidth":r["FontWidth"],
            "FontBlobHex":r["FontBlobHex"],
        })
    graphics=[]
    for r in resources["Graphics"]:
        graphics.append({
            "GraphicID":r["GraphicID"], "GraphicName":r["GraphicName"],
            "GraphicDescription":r["GraphicDescription"], "GraphicHeight":r["GraphicHeight"],
            "GraphicWidth":r["GraphicWidth"], "GraphicAllowMod":r["GraphicAllowMod"],
            "GraphicCType":r["GraphicCType"], "GraphicBlobHex":r["GraphicBlobHex"],
            "RedGraphicBlobHex":r.get("RedGraphicBlobHex"),
            "GreenGraphicBlobHex":r.get("GreenGraphicBlobHex"),
            "BlueGraphicBlobHex":r.get("BlueGraphicBlobHex"),
        })

    physical=[]
    for p in signs["PhysicalSigns"]:
        physical.append(enrich_physical_row(p, default_font_names))
    logical=[]
    for r in signs["LogicalSigns"]:
        logical.append({
            "LSignID":r["LSignID"], "LSignName":r["LSignName"],
            "LSignDescription":r["LSignDescription"], "LSignDotHeight":r["LSignDotHeight"],
            "LSignDotWidth":r["LSignDotWidth"],
        })

    # Stock IPS donor declares SignSetName as Text(20).  Keep the model valid
    # even when build_ips() is called directly rather than through the GUI.
    project_name = (project_name or "RECOVERED")[:20]
    signsets=[{
        "_local_id":1,
        "LoadModID":model["load_module_binding"]["load_mod_id"], "SignSetName":project_name,
        "SignSetDescription":"Recovered from compiled MTU", "SignSetOutputDate":datetime.datetime.now(),
        "SignSetOutputBytes":model["raw_mtu"], "Timing620":16, "Retention620":3,
        "SignSetOutputVersion": (
            model["compilation_metadata"]["output_version"]
            if model["compilation_metadata"]["output_version"] is not None else 0),
    }]
    return {
        "Fonts":fonts,"Graphics":graphics,"PhysicalSigns":physical,"LogicalSigns":logical,
        "SignSets":signsets,
    }


def _font_body_hash(blob: bytes) -> str | None:
    """Return an IPS font's compiled-body hash, ignoring its 28-byte label header."""
    if len(blob) < 28:
        return None
    return hashlib.sha256(blob[28:]).hexdigest()


def donor_font_bindings(db, fonts: list[dict]) -> tuple[dict[int, int], dict[int, str]]:
    """Match recovered font bodies to the donor's canonical font records."""
    by_body = {}
    rs = db.OpenRecordset("Fonts")
    try:
        while not rs.EOF:
            field = rs.Fields("Font")
            total = int(field.FieldSize)
            blob = bytearray()
            offset = 0
            while offset < total:
                part = field.GetChunk(offset, min(32768, total - offset))
                blob.extend(bytes(part))
                offset = len(blob)
            key = _font_body_hash(bytes(blob))
            if key and key not in by_body:
                by_body[key] = (int(rs.Fields("FontID").Value),
                                str(rs.Fields("FontFile").Value or ""))
            rs.MoveNext()
    finally:
        rs.Close()

    ids = {}
    names = {}
    for font in fonts:
        key = _font_body_hash(bytes.fromhex(font["FontBlobHex"]))
        match = by_body.get(key)
        if not match:
            continue
        font_id, font_file = match
        local_id = int(font["FontID"])
        ids[local_id] = font_id
        if font_file:
            names[int(font["CompiledFontIndex"])] = Path(font_file).stem
    return ids, names


GRAPHIC_BLOB_FIELDS = ("Graphic", "RedGraphic", "GreenGraphic", "BlueGraphic")


def _graphic_signature(height: int, width: int, blobs: list[bytes]) -> tuple | None:
    if not blobs or len(blobs[0]) <= 28:
        return None
    parts = []
    for blob in blobs:
        if not blob:
            parts.append(None)
        elif len(blob) <= 28:
            return None
        else:
            # Labels and the last two authoring-only header bytes are not compiled.
            parts.append(hashlib.sha256(blob[22:26] + blob[28:]).hexdigest())
    return int(height), int(width), tuple(parts)


def donor_graphic_bindings(db, graphics: list[dict]) -> tuple[dict[int, int], dict[int, str]]:
    """Reuse exact donor bitmaps, including compiled parameters and RGB planes."""
    by_signature = {}
    rs = db.OpenRecordset("SELECT * FROM [Graphics] ORDER BY [GraphicID]", 4)
    try:
        while not rs.EOF:
            name = str(rs.Fields("GraphicName").Value or "")
            if name != "#EFFDOT#":
                key = _graphic_signature(
                    rs.Fields("GraphicHeight").Value, rs.Fields("GraphicWidth").Value,
                    [bytes(rs.Fields(field).Value or b"") for field in GRAPHIC_BLOB_FIELDS])
                if key is not None and key not in by_signature:
                    by_signature[key] = (int(rs.Fields("GraphicID").Value), name)
            rs.MoveNext()
    finally:
        rs.Close()

    ids = {}
    names = {}
    for graphic in graphics:
        key = _graphic_signature(
            graphic["GraphicHeight"], graphic["GraphicWidth"],
            [bytes.fromhex(graphic.get(field + "BlobHex") or "")
             for field in GRAPHIC_BLOB_FIELDS])
        match = by_signature.get(key) if key is not None else None
        if match is not None:
            local_id = int(graphic["GraphicID"])
            ids[local_id], names[local_id] = match
    return ids, names


def _set_field(rs, key, value, blob_fields, pythoncom, VARIANT, *, table=None, field_info=None):
    if value is None:
        return
    target = blob_fields.get(key, key)
    if key in blob_fields:
        blob = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
        variant = VARIANT(pythoncom.VT_ARRAY | pythoncom.VT_UI1, list(blob))
        try:
            rs.Fields(target).AppendChunk(variant)
        except Exception as e:
            label = f"{table}.{target}" if table else target
            raise RuntimeError(f"{label} rejected binary payload of {len(blob)} bytes: {e}") from e
    else:
        fitted = _fit_field_value(value, (field_info or {}).get(target))
        if fitted is None:
            # AddNew initializes nullable fields to NULL.
            return
        try:
            rs.Fields(target).Value = fitted
        except Exception as e:
            label = f"{table}.{target}" if table else target
            raise RuntimeError(f"{label} rejected value {value!r}: {e}") from e


def append_autonumber_rows(db, table: str, rows: list[dict], id_field: str,
                           local_id_field: str | None = None,
                           blob_fields: dict[str, str] | None = None,
                           pythoncom=None, VARIANT=None, row_callback=None) -> dict[int, int]:
    """Insert rows without assigning an AutoNumber and return local->Jet ID map."""
    blob_fields = blob_fields or {}
    out = {}
    if not rows:
        return out
    fields = table_fields(db, table)
    field_info = table_field_info(db, table)
    rs = db.OpenRecordset(table, 2)  # dbOpenDynaset
    try:
        for ordinal,row in enumerate(rows, start=1):
            local_id = row.get(local_id_field or id_field, ordinal)
            rs.AddNew()
            for key,value in row.items():
                if key in {id_field, "_local_id"}:
                    continue
                target = blob_fields.get(key, key)
                if target not in fields:
                    continue
                _set_field(rs,key,value,blob_fields,pythoncom,VARIANT, table=table, field_info=field_info)
            try:
                rs.Update()
            except Exception as e:
                ident = {k: row.get(k) for k in ("MsgCode", "MsgClassID", "LSignID", "_local_id") if k in row}
                raise RuntimeError(f"{table} failed to save row {ident or row}: {e}") from e
            # AutoNumber is only guaranteed after moving to LastModified.
            rs.Bookmark = rs.LastModified
            out[int(local_id)] = int(rs.Fields(id_field).Value)
            if row_callback is not None:
                row_callback(table, ordinal, len(rows))
    finally:
        rs.Close()
    return out


def remap_dependent_rows(model: dict, maps: dict[str, dict[int,int]], signset_id: int) -> dict:
    signs=model["sign_tables"]
    font_map=maps["FontID"]; graph_map=maps["GraphicID"]
    p_map=maps["PSignID"]; l_map=maps["LSignID"]

    links=[]
    for r in signs["LogicalSignBuild"]:
        links.append({
            "LSignID":l_map[r["LSignID"]], "PSignID":p_map[r["PSignID"]],
            "PSignOriginX":r["PSignOriginX"], "PSignOriginY":r["PSignOriginY"],
            "PSignAddr":r["PSignAddr"],
        })
    ssbuild=[{"SignSetID":signset_id,"LSignID":l_map[r["LSignID"]]}
             for r in signs["SignSetBuild"]]

    frames=[]
    for r in model["db_frames"]:
        x=dict(r)
        # MsgFrameID is a Jet AutoNumber. Keep local value only for diagnostics;
        # append_autonumber_rows will not write it.
        x["LSignID"]=l_map[x["LSignID"]]
        if x["FontID"] is not None: x["FontID"]=font_map[x["FontID"]]
        if x["GraphicID"] is not None: x["GraphicID"]=graph_map[x["GraphicID"]]
        frames.append(x)
    zones=[]
    for r in model["effect_zones"]:
        x=dict(r)
        x["LSignID"]=l_map[x["LSignID"]]
        zones.append(x)

    color_zones=[]
    for r in model.get("color_zones",[]):
        x=dict(r)
        x["LSign"]=l_map[x.pop("LSignID")]
        color_zones.append(x)

    # IPS keeps one lock/property row for each message/sign combination. These
    # rows are application housekeeping rather than compiled MTU payload. The
    # message/sign cross product is recoverable, and unlocked is the conservative
    # default when lock state is not encoded in the MTU.
    msg_pairs=sorted({(int(r["MsgClassID"]),int(r["MsgCode"])) for r in frames})
    sign_props=[]
    local_id=0
    for cls,code in msg_pairs:
        for local_lsign in sorted(l_map):
            local_id += 1
            sign_props.append({
                "ID": local_id, "MsgCode": code, "MsgClassID": cls,
                "LSignID": l_map[local_lsign], "Locked": False,
            })
    return {
        "LogicalSignBuild":links,"SignSetBuild":ssbuild,
        "MessageFrames":frames,"EffectZones":zones,
        "ColorZone":color_zones,
        "SignMsgCodeProperties":sign_props,
    }


CLASS_C_KEY_FIELDS = ("MsgCode", "MsgClassID", "Approved")


def ensure_class_c_schema(db, layout: cce.ClassCLayout | cce.CustomLayout) -> None:
    """Make ClassCMsgs hold exactly the chosen elements (text + ID column each).

    Native IPS adds an element's columns when the element is created and drops
    them when it is deleted, so stale donor columns (e.g. Route/Destination when
    they are not chosen) are removed.  Text columns must allow zero-length
    strings: IPS's compiler reads them without Null checks ("Invalid use of Null").
    """
    others = {}
    rs = db.OpenRecordset("SELECT ElementID, ElementName FROM MsgClassElements WHERE MsgClassID <> 3", 4)
    try:
        while not rs.EOF:
            others[int(rs.Fields("ElementID").Value)] = str(rs.Fields("ElementName").Value)
            rs.MoveNext()
    finally:
        rs.Close()
    clashes = [f"{name} ({layout.element_id(name)} is {others[layout.element_id(name)]})"
               for name in layout.elements if layout.element_id(name) in others]
    if clashes:
        raise RuntimeError("Donor MsgClassElements already uses the Class C element ID(s): " + ", ".join(clashes))

    tdf = db.TableDefs("ClassCMsgs")
    wanted = {}
    for name in layout.elements:
        wanted[name] = 10
        wanted["ID" + name] = 4
    existing = {str(tdf.Fields(i).Name) for i in range(tdf.Fields.Count)}
    for name in sorted(existing - set(wanted) - set(CLASS_C_KEY_FIELDS)):
        tdf.Fields.Delete(name)
    for name, dtype in wanted.items():
        if name in existing:
            fld = tdf.Fields(name)
            if dtype == 10 and int(fld.Type) == 10 and not bool(fld.AllowZeroLength):
                fld.AllowZeroLength = True
            continue
        fld = tdf.CreateField(name, dtype, 255) if dtype == 10 else tdf.CreateField(name, dtype)
        if dtype == 10:
            fld.AllowZeroLength = True
        tdf.Fields.Append(fld)
    tdf.Fields.Refresh()
    missing = set(wanted) - {str(tdf.Fields(i).Name) for i in range(tdf.Fields.Count)}
    if missing:
        raise RuntimeError("Could not configure ClassCMsgs columns: " + ", ".join(sorted(missing)))
    # Physical column order follows the element order, after the key fields.
    for position, name in enumerate(list(CLASS_C_KEY_FIELDS) + list(wanted)):
        tdf.Fields(name).OrdinalPosition = position
    tdf.Fields.Refresh()


def configure_class_c_metadata(db, layout: cce.ClassCLayout | cce.CustomLayout, row_callback=None) -> None:
    db.Execute("DELETE FROM [MsgClassElements] WHERE [MsgClassID] = 3")
    db.Execute("DELETE FROM [MsgListingElements] WHERE [MsgClassID] = 3")
    append_rows(db, "MsgClassElements", layout.element_rows(), row_callback=row_callback)
    next_col_id = max_value(db, "MsgListingElements", "ColID") + 1
    listing_rows = [
        {"ColID": next_col_id + index, "MsgClassID": 3, "ColName": name, "ColWidth": width}
        for index, (name, width) in enumerate(layout.listing_columns())
    ]
    append_rows(db, "MsgListingElements", listing_rows, row_callback=row_callback)


def _scalar(db, sql: str, field: str = "N"):
    rs=db.OpenRecordset(sql)
    try:
        return rs.Fields(field).Value
    finally:
        rs.Close()


def _read_long_binary(db, sql: str, field_name: str) -> bytes:
    """Read a DAO Long Binary/OLE field in chunks for post-write verification."""
    rs=db.OpenRecordset(sql)
    try:
        fld=rs.Fields(field_name)
        total=int(fld.FieldSize)
        out=bytearray(); offset=0; chunk_size=32768
        while offset < total:
            part=fld.GetChunk(offset,min(chunk_size,total-offset))
            try:
                out.extend(bytes(part))
            except TypeError:
                out.extend(bytearray(part))
            offset=len(out)
        return bytes(out)
    finally:
        rs.Close()


def verify_written_database(db, model: dict) -> dict:
    """Verify row counts, message/sign cross product, and exact MTU BLOB."""
    expected={
        "PhysicalSigns":len(model["sign_tables"]["PhysicalSigns"]),
        "LogicalSigns":len(model["sign_tables"]["LogicalSigns"]),
        "LogicalSignBuild":len(model["sign_tables"]["LogicalSignBuild"]),
        "SignSetBuild":len(model["sign_tables"]["SignSetBuild"]),
        "EffectZones":len(model["effect_zones"]),
        "MessageFrames":len(model["db_frames"]),
        "ColorZone":len(model.get("color_zones",[])),
    }
    pairs={(int(r["MsgClassID"]),int(r["MsgCode"])) for r in model["db_frames"]}
    expected["SignMsgCodeProperties"]=len(pairs)*len(model["sign_tables"]["LogicalSigns"])
    expected["ClassAMsgs"]=sum(1 for c,_ in pairs if c==1)
    expected["ClassBMsgs"]=sum(1 for c,_ in pairs if c==2)
    expected["ClassCMsgs"]=sum(1 for c,_ in pairs if c==3)
    expected["ClassMsgs"]=0
    if "graphic_recovery" in model:
        expected["Graphics"] = model["graphic_recovery"]["expected_graphics"]
    actual={}
    errors=[]
    for table,n in expected.items():
        actual[table]=int(_scalar(db,f"SELECT Count(*) AS N FROM [{table}]"))
        if actual[table] != n:
            errors.append(f"{table}: expected {n}, got {actual[table]}")
    signsets=int(_scalar(db,"SELECT Count(*) AS N FROM [SignSets]"))
    actual["SignSets"]=signsets
    if signsets != 1:
        errors.append(f"SignSets: expected 1, got {signsets}")
    if signsets == 1 and "load_module_binding" in model:
        try:
            binding = model["load_module_binding"]
            version = model["compilation_metadata"]["output_version"]
            if version is None:
                version = 0
            rs = db.OpenRecordset("SELECT LoadModID, SignSetOutputVersion FROM SignSets", 4)
            try:
                saved_module_id = rs.Fields("LoadModID").Value
                saved_version = rs.Fields("SignSetOutputVersion").Value
            finally:
                rs.Close()
            if saved_module_id != binding["load_mod_id"] or saved_version != version:
                errors.append("Saved load module selection or output version differs from the recovered metadata")
            module = _read_long_binary(
                db, f"SELECT LOD FROM LoadModules WHERE LoadModID={binding['load_mod_id']}", "LOD")
            if (hashlib.sha256(module).hexdigest() != binding["donor_sha256"] or
                    _load_module_signature(module) != binding["signature"]):
                errors.append("Selected load module differs from the bound module")
        except Exception as e:
            errors.append(f"Could not verify compilation metadata: {e}")
    mtu_blob=b''
    if signsets == 1:
        try:
            mtu_blob=_read_long_binary(db,"SELECT TOP 1 SignSetOutput FROM SignSets","SignSetOutput")
            if mtu_blob != model["raw_mtu"]:
                errors.append(f"SignSetOutput differs from input MTU ({len(mtu_blob)} vs {len(model['raw_mtu'])} bytes)")
        except Exception as e:
            errors.append(f"Could not verify SignSetOutput BLOB: {e}")
    if "sign_catalog" in model:
        expected_metadata = Counter(
            (row["address"], row["part"], row["physical_name"],
             row["logical_name"], row["preview_color"])
            for row in model["sign_catalog"]["bindings"])
        try:
            rs = db.OpenRecordset(
                "SELECT b.PSignAddr, p.PSignPartNumber, p.PSignName, l.LSignName, p.PSignDotColor "
                "FROM (LogicalSignBuild AS b INNER JOIN PhysicalSigns AS p ON b.PSignID=p.PSignID) "
                "INNER JOIN LogicalSigns AS l ON b.LSignID=l.LSignID", 4)
            actual_metadata = Counter()
            try:
                while not rs.EOF:
                    actual_metadata[tuple(rs.Fields(i).Value for i in range(5))] += 1
                    rs.MoveNext()
            finally:
                rs.Close()
            if actual_metadata != expected_metadata:
                errors.append("Saved sign names, addresses, part numbers or preview colors differ from the model")
        except Exception as e:
            errors.append(f"Could not verify sign catalog metadata: {e}")
    if "graphic_recovery" in model:
        try:
            id_map = model["graphic_recovery"]["id_map"]
            rs = db.OpenRecordset("SELECT * FROM [Graphics]", 4)
            signatures = {}
            try:
                while not rs.EOF:
                    signatures[int(rs.Fields("GraphicID").Value)] = _graphic_signature(
                        rs.Fields("GraphicHeight").Value, rs.Fields("GraphicWidth").Value,
                        [bytes(rs.Fields(field).Value or b"") for field in GRAPHIC_BLOB_FIELDS])
                    rs.MoveNext()
            finally:
                rs.Close()
            for graphic in model["resources"]["Graphics"]:
                expected_signature = _graphic_signature(
                    graphic["GraphicHeight"], graphic["GraphicWidth"],
                    [bytes.fromhex(graphic.get(field + "BlobHex") or "")
                     for field in GRAPHIC_BLOB_FIELDS])
                graphic_id = id_map[int(graphic["GraphicID"])]
                if expected_signature is None or signatures.get(graphic_id) != expected_signature:
                    errors.append(f"Graphic {graphic_id}: saved bitmap, parameters or RGB planes differ")
            expected_usage = Counter(
                id_map[int(row["GraphicID"])] for row in model["db_frames"]
                if row.get("GraphicID") is not None)
            rs = db.OpenRecordset(
                "SELECT GraphicID, Count(*) AS N FROM MessageFrames "
                "WHERE GraphicID IS NOT NULL GROUP BY GraphicID", 4)
            actual_usage = Counter()
            try:
                while not rs.EOF:
                    actual_usage[int(rs.Fields("GraphicID").Value)] = int(rs.Fields("N").Value)
                    rs.MoveNext()
            finally:
                rs.Close()
            if actual_usage != expected_usage:
                errors.append("Saved message graphic usages differ from the remapped model")
        except Exception as e:
            errors.append(f"Could not verify recovered graphics: {e}")
    return {
        "status":"PASS" if not errors else "FAIL",
        "expected_counts":expected, "actual_counts":actual,
        "mtu_expected_sha256":hashlib.sha256(model["raw_mtu"]).hexdigest(),
        "mtu_written_sha256":hashlib.sha256(mtu_blob).hexdigest() if mtu_blob else None,
        "errors":errors,
    }


def build_ips(mtu_path: Path, template_path: Path, out_path: Path, project_name: str,
              class_c_layout: cce.ClassCLayout | cce.CustomLayout | None = None, progress_callback=None,
              best_effort: bool = False):
    def report_progress(percent: int, message: str) -> None:
        if progress_callback is not None:
            progress_callback(percent, message)

    if template_path.resolve() == out_path.resolve():
        raise ValueError("Output path must differ from the template")
    report_progress(5, "Reading and decoding MTU...")
    model=build_model(mtu_path, class_c_layout, best_effort=best_effort)
    report_progress(30, "Validating recovered model...")
    preflight=preflight_model(model)
    if preflight["status"] != "PASS":
        raise RuntimeError("MTU preflight failed: " + "; ".join(preflight["errors"]))
    report_progress(40, "Preparing output database...")
    shutil.copy2(template_path, out_path)
    # Zip extraction or donor media can mark Donor.ips read-only.  Always make
    # the working copy writable before DAO opens it.
    try:
        os.chmod(out_path, 0o666)
    except OSError:
        pass
    report_progress(50, "Opening output database...")
    pythoncom, VARIANT, engine, db=open_dao(out_path, exclusive=True)
    ws=engine.Workspaces(0)
    try:
        model["load_module_binding"] = ensure_load_module(
            engine, db, template_path, model, pythoncom=pythoncom, VARIANT=VARIANT)
        if model["load_module_binding"]["source"] != "donor":
            message = (f"Controller module {model['load_module_binding']['description']} was "
                       f"{model['load_module_binding']['source']}.")
            if model["load_module_binding"]["source"] == "rebuilt from the MTU":
                message += (" Its header fields are rewritten by IPS on compile; confirm the project "
                            "compiles in IPS before relying on it.")
            model["compilation_metadata"]["warnings"].append(message)
        catalog, catalog_warnings = load_sign_catalog(engine, db, template_path)
        model["sign_catalog"] = apply_sign_catalog(model["sign_tables"], catalog, catalog_warnings)
        preflight = preflight_model(model)
        classes=class_message_rows(model)
        layout=model["class_c_layout"]
        ensure_class_c_schema(db, layout)
        ws.BeginTrans()
        try:
            # A blank Donor.ips database contains the required resource/schema objects
            # without project rows. Clearing these tables also supports other
            # structurally compatible donor databases.
            for table in ("MessageFrames","EffectZones","LogicalSignBuild","SignSetBuild",
                          "LogicalSigns","PhysicalSigns","SignSets","SignMsgCodeProperties",
                          "ClassAMsgs","ClassBMsgs","ClassCMsgs","ClassMsgs","ClassTemplates","TemplateZones",
                          "ColorZone"):
                try:
                    clear_table(db, table)
                except Exception:
                    # Some older donors may not contain every optional authoring table.
                    pass

            font_map, default_font_names = donor_font_bindings(db, model["resources"]["Fonts"])
            base=prepare_rows(model, project_name, default_font_names)
            missing_fonts=[r for r in base["Fonts"] if int(r["FontID"]) not in font_map]
            graph_map, graphic_names = donor_graphic_bindings(db, base["Graphics"])
            missing_graphics = [
                row for row in base["Graphics"] if int(row["GraphicID"]) not in graph_map]
            model["graphic_recovery"] = {
                "reused": [
                    {"local_id": local_id, "graphic_id": graphic_id, "name": graphic_names[local_id]}
                    for local_id, graphic_id in graph_map.items()],
                "inserted": len(missing_graphics),
                "expected_graphics": int(_scalar(db, "SELECT Count(*) AS N FROM Graphics"))
                + len(missing_graphics),
            }
            message_pairs = {(int(row["MsgClassID"]), int(row["MsgCode"])) for row in model["db_frames"]}
            write_counts = [
                ("Fonts", len(missing_fonts)), ("Graphics", len(missing_graphics)),
                ("PhysicalSigns", len(base["PhysicalSigns"])), ("LogicalSigns", len(base["LogicalSigns"])),
                ("SignSets", len(base["SignSets"])), ("LogicalSignBuild", len(model["sign_tables"]["LogicalSignBuild"])),
                ("SignSetBuild", len(model["sign_tables"]["SignSetBuild"])), ("EffectZones", len(model["effect_zones"])),
                ("MessageFrames", len(model["db_frames"])), ("ColorZone", len(model.get("color_zones", []))),
                ("SignMsgCodeProperties", len(message_pairs) * len(model["sign_tables"]["LogicalSigns"])),
                ("Class C metadata", len(layout.element_rows()) + len(layout.listing_columns())),
                *[(table, len(rows)) for table, rows in classes.items()],
            ]
            total_write_rows = sum(count for _, count in write_counts)
            completed_write_rows = 0
            last_write_percent = 54

            def report_written_row(table: str, ordinal: int, row_count: int) -> None:
                nonlocal completed_write_rows, last_write_percent
                completed_write_rows += 1
                percent = 55 + (35 * completed_write_rows // max(1, total_write_rows))
                if percent > last_write_percent:
                    last_write_percent = percent
                    report_progress(percent, f"Writing {table}: {completed_write_rows:,}/{total_write_rows:,} rows...")

            report_progress(55, f"Writing recovered data: 0/{total_write_rows:,} rows...")
            configure_class_c_metadata(db, layout, report_written_row)
            font_map.update(append_autonumber_rows(
                db,"Fonts",missing_fonts,"FontID",blob_fields={"FontBlobHex":"Font"},
                pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            )
            graph_map.update(append_autonumber_rows(
                db,"Graphics",missing_graphics,"GraphicID",blob_fields={
                    "GraphicBlobHex":"Graphic", "RedGraphicBlobHex":"RedGraphic",
                    "GreenGraphicBlobHex":"GreenGraphic", "BlueGraphicBlobHex":"BlueGraphic",
                },
                pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row))
            model["graphic_recovery"]["id_map"] = graph_map
            p_map=append_autonumber_rows(
                db,"PhysicalSigns",base["PhysicalSigns"],"PSignID",
                pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            l_map=append_autonumber_rows(
                db,"LogicalSigns",base["LogicalSigns"],"LSignID",
                pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            ss_map=append_autonumber_rows(
                db,"SignSets",base["SignSets"],"SignSetID",local_id_field="_local_id",
                blob_fields={"SignSetOutputBytes":"SignSetOutput"},
                pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)

            dep=remap_dependent_rows(model,{
                "FontID":font_map,"GraphicID":graph_map,"PSignID":p_map,"LSignID":l_map,
            },ss_map[1])
            append_rows(db,"LogicalSignBuild",dep["LogicalSignBuild"],pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            append_rows(db,"SignSetBuild",dep["SignSetBuild"],pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            append_autonumber_rows(db,"EffectZones",dep["EffectZones"],"EffZoneID",
                                   pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            append_autonumber_rows(db,"MessageFrames",dep["MessageFrames"],"MsgFrameID",
                                   pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            append_autonumber_rows(db,"ColorZone",dep["ColorZone"],"ID",
                                   pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            append_autonumber_rows(db,"SignMsgCodeProperties",dep["SignMsgCodeProperties"],"ID",
                                   pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            for table,rows in classes.items():
                append_rows(db,table,rows,pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            ws.CommitTrans()
        except Exception:
            ws.Rollback()
            raise
        report_progress(90, "Verifying recovered database...")
        verification=verify_written_database(db,model)
        verification["preflight"] = preflight
        verification["recovery_mode"] = preflight["recovery_mode"]
        verification["warnings"] = preflight["warnings"]
        verification["sign_catalog"] = model["sign_catalog"]
        verification["graphic_recovery"] = model["graphic_recovery"]
        verification["compilation_metadata"] = model["compilation_metadata"]
        verification["load_module_binding"] = model["load_module_binding"]
        verification["class_c_layout"] = layout.describe()
    finally:
        try:
            db.Close()
        finally:
            # Balance CoInitialize() from open_dao() on this worker thread.
            pythoncom.CoUninitialize()
    report_path=out_path.with_suffix(out_path.suffix + ".verify.json")
    report_path.write_text(json.dumps(verification,indent=2),encoding="utf-8")
    if verification["status"] != "PASS":
        raise RuntimeError(f"Database write completed but verification failed; see {report_path}")
    report_progress(100, "Conversion complete.")
    return model, verification

def main():
    ap=argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", type=Path, nargs="+", metavar="PATH",
                    help="input.mtu output.ips (the older input.mtu donor.ips output.ips form is still accepted)")
    ap.add_argument("--donor", type=Path, help="donor IPS database; defaults to the bundled Donor.ips")
    ap.add_argument("--name", default="RECOVERED", help="new SignSetName")
    ap.add_argument("--class-c-elements", default="auto", metavar="LIST",
                    help="comma-separated Class C elements to create, from "
                         + ", ".join(cce.ELEMENTS) + " (MainFront is required); "
                         "'auto' suggests them from the MTU")
    ap.add_argument("--class-c-preset", type=Path, metavar="JSON",
                    help="custom Class C element names saved from the GUI's Custom elements dialog")
    ap.add_argument("--preflight-only", action="store_true", help="parse/validate MTU without opening DAO or writing an IPS")
    ap.add_argument("--best-effort", action="store_true",
                    help="preserve decoded anomalies with warnings; editable appearance is unverified")
    args=ap.parse_args()
    if len(args.paths) == 2:
        args.mtu, args.output = args.paths
    elif len(args.paths) == 3 and not args.donor:
        args.mtu, args.donor, args.output = args.paths
    else:
        ap.error("expected: input.mtu output.ips")
    if not args.preflight_only:
        args.donor = args.donor or bundled_donor()
        if args.donor is None or not args.donor.is_file():
            ap.error(f"{DONOR_FILENAME} was not found beside the converter; pass --donor PATH")
    if args.class_c_preset and args.class_c_elements.strip().lower()!="auto":
        ap.error("--class-c-preset and --class-c-elements cannot be combined")
    if args.class_c_preset:
        layout=cce.load_preset(args.class_c_preset)
    else:
        layout=(None if args.class_c_elements.strip().lower()=="auto"
                else cce.ClassCLayout.parse(args.class_c_elements))
    if args.preflight_only:
        report=preflight_model(build_model(
            args.mtu,layout,best_effort=args.best_effort))
        print(json.dumps(report,indent=2))
        raise SystemExit(0 if report["status"]=="PASS" else 2)
    model,verification=build_ips(
        args.mtu,args.donor,args.output,args.name,layout,
        best_effort=args.best_effort)
    print(f"Wrote {args.output}")
    print("Class C elements: " + ", ".join(model["class_c_layout"].elements))
    for warning in verification["warnings"]:
        print(f"WARNING: {warning}")
    print(f"Verification: {verification['status']} ({args.output}.verify.json)")

if __name__=="__main__":
    main()
