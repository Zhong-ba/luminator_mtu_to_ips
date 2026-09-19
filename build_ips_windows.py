#!/usr/bin/env python3
"""Build an editable Luminator IPS .ips database from a compiled .mtu.

Windows writer paired with mtu_reverse.py. It auto-detects both legacy
Class-C Route/Destination/SmallSide and expanded five-field Class-C projects.  Parsing/reconstruction is
platform-independent; writing the old Microsoft Jet database is deliberately
performed through Microsoft's DAO engine on Windows instead of manufacturing
Jet pages by hand.

Requirements on the Windows machine:
  * Luminator IPS / a Jet-capable Microsoft runtime
  * Python (32-bit is safest with legacy Jet/DAO)
  * pywin32:  py -m pip install pywin32

Usage:
    py build_ips_windows.py input.mtu Donor.ips recovered.ips --name RECOVERED

Donor.ips is the bundled Luminator IPS database because
it is a plain Jet 3 donor with built-in resource libraries and no project rows.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mtu_reverse as mr


def build_model(mtu_path: Path, class_c_profile: str = "auto") -> dict:
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
    runtime_frames = mr.reconstruct_messageframes(banks, font_metrics, sign_tables, graphic_metrics)
    runtime_frames = mr.assign_color_frame_numbers(runtime_frames)
    runtime_frames = mr.collapse_compiler_rgb_placeholders(runtime_frames)
    color_zones = mr.reconstruct_color_zones(runtime_frames, sign_tables)
    frames = mr.collapse_color_plane_frames(runtime_frames)
    resources = mr.reconstruct_resource_tables(
        raw, mtu, fheaders, gheaders, frames, sign_tables)
    zones = mr.reconstruct_effect_zones(frames, sign_tables)
    resolved_profile = (mr.infer_class_c_profile(sign_tables) if (class_c_profile or "auto").lower() == "auto"
                        else (class_c_profile or "expanded").lower())
    db_frames = mr.database_ready_messageframes(frames, resources, sign_tables, resolved_profile)

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
        "class_c_profile": resolved_profile,
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
    errors=[]; warnings=[]; unresolved=[]; unknown_masks=[]
    unknown_token_catalog = identify_unknown_message_tokens(model)
    segment_count=0; control_count=0
    message_records=0
    message_classes = {}
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
                        if tok.get("semantic") == "unresolved": unresolved.append(tok.get("opcode"))
                    elif tok.get("kind") == "byte":
                        unresolved.append(f"byte_0x{int(tok.get('value',0)):02X}")
    if unknown_masks:
        errors.append(f"unknown sign selector masks: {sorted(set(unknown_masks))}")
    if unresolved:
        errors.append(f"unresolved message controls: {dict(defaultdict(int)) if False else sorted(set(unresolved))}")
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
    for i,r in enumerate(model["db_frames"]):
        if int(r["LSignID"]) not in lsign_ids: errors.append(f"frame {i} references unknown LSignID {r['LSignID']}")
        if r.get("FontID") is not None and int(r["FontID"]) not in font_ids: errors.append(f"frame {i} references unknown FontID {r['FontID']}")
        if r.get("GraphicID") is not None and int(r["GraphicID"]) not in graph_ids: errors.append(f"frame {i} references unknown GraphicID {r['GraphicID']}")
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
        "mtu_sha256":hashlib.sha256(model["raw_mtu"]).hexdigest(),
        "class_c_profile":model.get("class_c_profile","auto"),
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
    profile=model.get("class_c_profile","expanded")
    cc_by_code = {int(r["MsgCode"]): r for r in mr.reconstruct_class_c_by_profile(frames, model["sign_tables"], profile)}
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
            recovered = dict(cc_by_code[int(code)])
            if profile == "legacy":
                for key in ("Route","Destination","SmallSide"):
                    recovered[key]=str(recovered.get(key,""))[:255]
            else:
                # Retain the donor's old Destination pair as a compatibility
                # summary while the five expanded fields remain authoritative.
                recovered["Destination"] = recovered.get("DestinationTop", "")[:255]
                recovered["IDDestination"] = 7
                for key in ("Route", "DestinationTop", "DestinationBot", "DestinationSide", "RouteSide"):
                    recovered[key] = str(recovered.get(key, ""))[:255]
            out["ClassCMsgs"].append(recovered)
    return out


def class_message_element_rows(classes: dict[str, list[dict]], profile: str) -> list[dict]:
    """Normalize authoring fields into the compiler's ClassMsgs element table."""
    if profile == "legacy":
        class_c_fields = (("Route", "IDRoute"), ("Destination", "IDDestination"),
                          ("SmallSide", "IDSmallSide"))
    else:
        class_c_fields = (("Route", "IDRoute"), ("DestinationTop", "IDDestinationTop"),
                          ("DestinationBot", "IDDestinationBot"),
                          ("DestinationSide", "IDDestinationSide"),
                          ("RouteSide", "IDRouteSide"))
    field_map = {
        "ClassAMsgs": (("Title", "IDTitle"), ("Text", "IDText")),
        "ClassBMsgs": (("PRText", "IDPRText"), ("PRBot", "IDPRBot"),
                        ("PRSide", "IDPRSide")),
        "ClassCMsgs": class_c_fields,
    }
    out = []
    for table, fields in field_map.items():
        for row in classes.get(table, []):
            for text_field, id_field in fields:
                text = str(row.get(text_field) or "")
                element_id = row.get(id_field)
                if not text or element_id is None:
                    continue
                out.append({
                    "MsgCode": int(row["MsgCode"]),
                    "MsgClassID": int(row["MsgClassID"]),
                    "ElementID": int(element_id),
                    "ElementText": text,
                    "Approved": bool(row.get("Approved", True)),
                })
    return out


def enrich_physical_row(p: dict, default_font_names: dict[int, str] | None = None) -> dict:
    is_matrix = p["PSignType"] == "Matrix"
    default_font = (default_font_names or {}).get(
        int(p["DefaultFontIndex"]), f"Recovered{int(p['DefaultFontIndex']):02d}")
    return {
        "PSignID": p["PSignID"],
        "PSignName": p["PSignName"],
        "PSignDescription": "Recovered from compiled MTU",
        "PSignPartNumber": p["PSignPartNumber"],
        "PSignType": p["PSignType"], "PSignDotShape": "Round", "PSignDotAspect": "1/1",
        "PSignDotHeight": p["PSignDotHeight"], "PSignDotWidth": p["PSignDotWidth"],
        "PSignCharWidth": p["PSignCharWidth"], "PSignAllowMod": False,
        "PSignDotColor": 33023, "PSignCharLines": p["PSignCharLines"],
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
    if exclusive and any("in use" in error.lower() or "lock" in error.lower() for error in errors):
        raise RuntimeError(
            "[OUTPUT_IN_USE] The output IPS database is open in Luminator IPS or another Jet/DAO process. "
            "Close it completely, then retry the conversion.\n"
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
    Jet distinguishes an empty text string from NULL.  Several IPS authoring
    columns (notably expanded Class-C fields such as DestinationBot) disallow
    zero-length strings but happily accept NULL for an unused value.
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
    * ``""`` becomes NULL when ``AllowZeroLength`` is false.  This mirrors
      native IPS projects, where unused Class-C authoring fields are NULL rather
      than zero-length strings.
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
        "LoadModID":2, "SignSetName":project_name,
        "SignSetDescription":"Recovered from compiled MTU", "SignSetOutputDate":datetime.datetime.now(),
        "SignSetOutputBytes":model["raw_mtu"], "Timing620":16, "Retention620":3,
        "SignSetOutputVersion":99,
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


def ensure_legacy_class_c_schema(db) -> None:
    """Upgrade the blank donor to legacy Route/Destination/SmallSide shape."""
    tdf=db.TableDefs("ClassCMsgs")
    existing={str(tdf.Fields(i).Name) for i in range(tdf.Fields.Count)}
    for name,dtype,size in (("SmallSide",10,255),("IDSmallSide",4,None)):
        if name in existing:continue
        fld=tdf.CreateField(name,dtype,size) if size else tdf.CreateField(name,dtype)
        tdf.Fields.Append(fld); existing.add(name)
    missing={"SmallSide","IDSmallSide"}-existing
    if missing:raise RuntimeError("Could not add legacy ClassC fields: "+", ".join(sorted(missing)))


def ensure_expanded_class_c_schema(db) -> None:
    """Upgrade an old Donor.ips ClassCMsgs table to the five-field IPS layout.

    The stock blank donor has Route + Destination.  Newer projects may also use
    DestinationTop, DestinationBot, DestinationSide and RouteSide.  Adding these
    authoring columns is non-destructive; the legacy Destination pair is retained.
    """
    tdf = db.TableDefs("ClassCMsgs")
    existing = {str(tdf.Fields(i).Name) for i in range(tdf.Fields.Count)}
    # DAO DataTypeEnum: dbLong=4, dbText=10.
    defs = [
        ("DestinationTop", 10, 255), ("IDDestinationTop", 4, None),
        ("DestinationBot", 10, 255), ("IDDestinationBot", 4, None),
        ("DestinationSide", 10, 255), ("IDDestinationSide", 4, None),
        ("RouteSide", 10, 255), ("IDRouteSide", 4, None),
    ]
    for name, dtype, size in defs:
        if name in existing:
            continue
        fld = tdf.CreateField(name, dtype, size) if size else tdf.CreateField(name, dtype)
        tdf.Fields.Append(fld)
        existing.add(name)
    required = {x[0] for x in defs}
    missing = required - existing
    if missing:
        raise RuntimeError("Could not expand ClassCMsgs schema: missing " + ", ".join(sorted(missing)))


def ensure_class_message_element_key(db) -> None:
    """Allow one ClassMsgs row for each authoring element of a message."""
    tdf = db.TableDefs("ClassMsgs")
    key_fields = ("MsgCode", "MsgClassID", "ElementID")
    restrictive = []
    for index in range(tdf.Indexes.Count):
        idx = tdf.Indexes(index)
        fields = tuple(str(idx.Fields(field_index).Name) for field_index in range(idx.Fields.Count))
        if bool(idx.Primary) and fields == key_fields:
            return
        if bool(idx.Primary) and fields == key_fields[:2]:
            restrictive.append(str(idx.Name))
    for name in restrictive:
        tdf.Indexes.Delete(name)
    if restrictive:
        index = tdf.CreateIndex("PrimaryKey")
        index.Primary = True
        index.Unique = True
        for field_name in key_fields:
            index.Fields.Append(index.CreateField(field_name))
        tdf.Indexes.Append(index)
    else:
        raise RuntimeError("ClassMsgs primary key does not match a supported donor schema")


def adapt_to_donor_schema(db, dep: dict, classes: dict, profile: str) -> None:
    fields=table_fields(db,"ClassCMsgs")
    if profile=="legacy":
        required={"Route","IDRoute","Destination","IDDestination","SmallSide","IDSmallSide"}
    else:
        required={"DestinationTop","IDDestinationTop","DestinationBot","IDDestinationBot",
                  "DestinationSide","IDDestinationSide","RouteSide","IDRouteSide"}
    missing=required-fields
    if missing:
        raise RuntimeError(f"{profile} ClassCMsgs schema is unavailable: "+", ".join(sorted(missing)))


def class_c_metadata_rows(profile: str) -> tuple[list[dict], list[tuple[str, int]]]:
    if profile == "expanded":
        return (
            [
                {"ElementID": 6, "MsgClassID": 3, "ElementName": "Route", "ElementDescription": "Route number"},
                {"ElementID": 14, "MsgClassID": 3, "ElementName": "DestinationTop", "ElementDescription": "Top destination"},
                {"ElementID": 15, "MsgClassID": 3, "ElementName": "DestinationBot", "ElementDescription": "Bottom destination"},
                {"ElementID": 16, "MsgClassID": 3, "ElementName": "DestinationSide", "ElementDescription": "Side destination"},
                {"ElementID": 17, "MsgClassID": 3, "ElementName": "RouteSide", "ElementDescription": "Side route"},
            ],
            [("MsgCode", 900), ("Locked", 700), ("Route", 1500),
             ("DestinationTop", 3000), ("DestinationBot", 3000),
             ("DestinationSide", 3000), ("RouteSide", 1500)],
        )
    return (
        [
            {"ElementID": 6, "MsgClassID": 3, "ElementName": "Route", "ElementDescription": "Route number"},
            {"ElementID": 7, "MsgClassID": 3, "ElementName": "Destination", "ElementDescription": "Destination"},
            {"ElementID": 14, "MsgClassID": 3, "ElementName": "SmallSide", "ElementDescription": "Small side destination"},
        ],
        [("MsgCode", 900), ("Locked", 700), ("Route", 3000),
         ("Destination", 3000), ("SmallSide", 3000)],
    )


def configure_class_c_metadata(db, profile: str, row_callback=None) -> None:
    elements, columns = class_c_metadata_rows(profile)
    db.Execute("DELETE FROM [MsgClassElements] WHERE [MsgClassID] = 3")
    db.Execute("DELETE FROM [MsgListingElements] WHERE [MsgClassID] = 3")
    append_rows(db, "MsgClassElements", elements, row_callback=row_callback)
    next_col_id = max_value(db, "MsgListingElements", "ColID") + 1
    listing_rows = [
        {"ColID": next_col_id + index, "MsgClassID": 3, "ColName": name, "ColWidth": width}
        for index, (name, width) in enumerate(columns)
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
    expected["ClassMsgs"]=len(class_message_element_rows(
        class_message_rows(model), model.get("class_c_profile", "expanded")))
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
    mtu_blob=b''
    if signsets == 1:
        try:
            mtu_blob=_read_long_binary(db,"SELECT TOP 1 SignSetOutput FROM SignSets","SignSetOutput")
            if mtu_blob != model["raw_mtu"]:
                errors.append(f"SignSetOutput differs from input MTU ({len(mtu_blob)} vs {len(model['raw_mtu'])} bytes)")
        except Exception as e:
            errors.append(f"Could not verify SignSetOutput BLOB: {e}")
    return {
        "status":"PASS" if not errors else "FAIL",
        "expected_counts":expected, "actual_counts":actual,
        "mtu_expected_sha256":hashlib.sha256(model["raw_mtu"]).hexdigest(),
        "mtu_written_sha256":hashlib.sha256(mtu_blob).hexdigest() if mtu_blob else None,
        "errors":errors,
    }


def build_ips(mtu_path: Path, template_path: Path, out_path: Path, project_name: str,
              class_c_profile: str = "auto", progress_callback=None):
    def report_progress(percent: int, message: str) -> None:
        if progress_callback is not None:
            progress_callback(percent, message)

    if template_path.resolve() == out_path.resolve():
        raise ValueError("Output path must differ from the template")
    report_progress(5, "Reading and decoding MTU...")
    model=build_model(mtu_path, class_c_profile)
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
        classes=class_message_rows(model)
        class_elements=class_message_element_rows(classes, model["class_c_profile"])
        if model["class_c_profile"]=="legacy":
            ensure_legacy_class_c_schema(db)
        else:
            ensure_expanded_class_c_schema(db)
        ensure_class_message_element_key(db)
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
            message_pairs = {(int(row["MsgClassID"]), int(row["MsgCode"])) for row in model["db_frames"]}
            metadata_elements, metadata_columns = class_c_metadata_rows(model["class_c_profile"])
            write_counts = [
                ("Fonts", len(missing_fonts)), ("Graphics", len(base["Graphics"])),
                ("PhysicalSigns", len(base["PhysicalSigns"])), ("LogicalSigns", len(base["LogicalSigns"])),
                ("SignSets", len(base["SignSets"])), ("LogicalSignBuild", len(model["sign_tables"]["LogicalSignBuild"])),
                ("SignSetBuild", len(model["sign_tables"]["SignSetBuild"])), ("EffectZones", len(model["effect_zones"])),
                ("MessageFrames", len(model["db_frames"])), ("ColorZone", len(model.get("color_zones", []))),
                ("SignMsgCodeProperties", len(message_pairs) * len(model["sign_tables"]["LogicalSigns"])),
                ("Class-C metadata", len(metadata_elements) + len(metadata_columns)),
                ("ClassMsgs", len(class_elements)),
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
            configure_class_c_metadata(db, model["class_c_profile"], report_written_row)
            font_map.update(append_autonumber_rows(
                db,"Fonts",missing_fonts,"FontID",blob_fields={"FontBlobHex":"Font"},
                pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            )
            graph_map=append_autonumber_rows(
                db,"Graphics",base["Graphics"],"GraphicID",blob_fields={
                    "GraphicBlobHex":"Graphic", "RedGraphicBlobHex":"RedGraphic",
                    "GreenGraphicBlobHex":"GreenGraphic", "BlueGraphicBlobHex":"BlueGraphic",
                },
                pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
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
            adapt_to_donor_schema(db, dep, classes, model["class_c_profile"])
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
            append_rows(db,"ClassMsgs",class_elements,pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            for table,rows in classes.items():
                append_rows(db,table,rows,pythoncom=pythoncom,VARIANT=VARIANT,row_callback=report_written_row)
            ws.CommitTrans()
        except Exception:
            ws.Rollback()
            raise
        report_progress(90, "Verifying recovered database...")
        verification=verify_written_database(db,model)
        verification["preflight"] = preflight
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
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mtu", type=Path)
    ap.add_argument("template", type=Path, help="donor IPS database; Donor.ips is included in releases")
    ap.add_argument("output", type=Path)
    ap.add_argument("--name", default="RECOVERED", help="new SignSetName")
    ap.add_argument("--class-c-profile", choices=("auto","legacy","expanded"), default="auto",
                    help="Class-C authoring schema; auto infers from compiled hardware")
    ap.add_argument("--preflight-only", action="store_true", help="parse/validate MTU without opening DAO or writing an IPS")
    args=ap.parse_args()
    if args.preflight_only:
        report=preflight_model(build_model(args.mtu,args.class_c_profile))
        print(json.dumps(report,indent=2))
        raise SystemExit(0 if report["status"]=="PASS" else 2)
    _,verification=build_ips(args.mtu,args.template,args.output,args.name,args.class_c_profile)
    print(f"Wrote {args.output}")
    print(f"Verification: {verification['status']} ({args.output}.verify.json)")

if __name__=="__main__":
    main()
