#!/usr/bin/env python3
"""Luminator IPS/MTU reverse-engineering extractor.

Targets the MTU layout produced by the IPS 3.x compiler. This module performs
the platform-independent MTU parsing/decompilation stage.
The companion build_ips_windows.py module writes the recovered model into an
editable Jet/IPS database on Windows.

Recovered:
  * master table / section directory
  * 256-byte physical-sign table
  * 16-byte configuration records
  * font headers and exact font blobs
  * graphic headers and exact graphic blobs
  * 16-byte listing/sign records
  * message banks A-K, split into FE-delimited records
  * printable text and high-level control tokens from each message record
  * optional proof that an MTU is embedded in a source IPS Jet database

All offsets are preserved in the JSON manifest so later opcode decoding can be
added without changing the extraction format.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

DEFAULT_LOAD_BASE = 0x30000
SECTION_NAMES = [
    "physical_config",
    "configuration_records",
    "fonts",
    "graphics",
    "listing_config",
    "messages_A",
    "messages_B",
    "messages_C",
    "messages_D",
    "messages_E",
    "messages_F",
    "messages_G",
    "messages_H",
    "messages_I",
    "messages_J",
    "messages_K",
]

# Parameter counts for known IPS 3.x message controls. Unknown control codes
# are preserved as one-byte controls rather than discarded.
CONTROL_PARAM_COUNTS = {
    0xF0: 0,
    0xF1: 0,
    0xF2: 4,
    0xF3: 4,
    0xF4: 2,
    0xF5: 2,
    0xF6: 2,
    0xF7: 2,
    0xF8: 2,
    0xF9: 2,
    0xFA: 2,
    0xFB: 2,
    0xFC: 2,
    0xFD: 0,
    0xFE: 0,  # bank/message delimiter; normally removed before tokenizing
    0xFF: 0,
}

COLOR_PLANES = {
    0x80: (0x01, 255), 0x90: (0x01, 128),
    0x40: (0x02, 255), 0x50: (0x02, 128),
    0x20: (0x04, 255), 0x30: (0x04, 128),
}


def be16(b: bytes, off: int = 0) -> int:
    return struct.unpack_from(">H", b, off)[0]


def be32(b: bytes, off: int = 0) -> int:
    return struct.unpack_from(">I", b, off)[0]


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def ascii_runs(data: bytes, min_len: int = 3) -> list[dict]:
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append({
            "offset": m.start(),
            "text": m.group().decode("ascii", "replace"),
        })
    return out


def tokenize_message(data: bytes) -> list[dict]:
    """Lossless-ish readable token stream.

    Text runs, inferred controls, and otherwise-unclassified bytes are emitted.
    The original record is also retained as a .bin file, so no information is
    lost if an inferred opcode length later proves wrong.
    """
    toks = []
    i = 0
    while i < len(data):
        c = data[i]
        if 0x20 <= c <= 0x7E:
            j = i + 1
            while j < len(data) and 0x20 <= data[j] <= 0x7E:
                j += 1
            toks.append({"kind": "text", "offset": i,
                         "text": data[i:j].decode("ascii", "replace")})
            i = j
            continue
        if c in CONTROL_PARAM_COUNTS:
            n = CONTROL_PARAM_COUNTS[c]
            end = min(len(data), i + 1 + n)
            toks.append({
                "kind": "control",
                "offset": i,
                "opcode": f"0x{c:02X}",
                "params_hex": data[i + 1:end].hex(" "),
            })
            i = end
            continue
        toks.append({"kind": "byte", "offset": i, "value": f"0x{c:02X}"})
        i += 1
    return toks


@dataclass
class Section:
    index: int
    name: str
    address: int
    offset: int
    end_offset: int

    @property
    def length(self) -> int:
        return self.end_offset - self.offset


class MTU:
    def __init__(self, data: bytes, load_base: int = DEFAULT_LOAD_BASE):
        self.data = data
        self.load_base = load_base
        self.master_address = be32(data, 0)
        self.master_offset = self.master_address - load_base
        if self.master_offset < 0 or self.master_offset + 64 > len(data):
            raise ValueError(
                f"Master pointer 0x{self.master_address:08X} does not resolve "
                f"inside file with load base 0x{load_base:X}"
            )
        self.master = list(struct.unpack_from(">16I", data, self.master_offset))
        self._validate_master()
        self.sections = self._sections()

    def _validate_master(self) -> None:
        offsets = [x - self.load_base for x in self.master]
        if any(x < 0 or x > len(self.data) for x in offsets):
            raise ValueError("One or more master-table pointers fall outside the MTU")
        if offsets != sorted(offsets):
            raise ValueError("Master-table pointers are not monotonically increasing")

    def _sections(self) -> list[Section]:
        out = []
        for i, (name, addr) in enumerate(zip(SECTION_NAMES, self.master)):
            off = addr - self.load_base
            if i + 1 < len(self.master):
                end = self.master[i + 1] - self.load_base
            else:
                end = len(self.data)
            out.append(Section(i, name, addr, off, end))
        return out

    def section_data(self, i: int) -> bytes:
        s = self.sections[i]
        return self.data[s.offset:s.end_offset]


def parse_fixed_records(data: bytes, width: int = 16) -> tuple[list[dict], bytes]:
    n = len(data) // width
    # Fixed-record sections may end in a two-byte terminator; preserve any
    # remainder explicitly instead of guessing its meaning.
    if len(data) % width == 2:
        n = (len(data) - 2) // width
    records = []
    for i in range(n):
        r = data[i * width:(i + 1) * width]
        records.append({
            "index": i,
            "hex": r.hex(" "),
            "u16be": [be16(r, j) for j in range(0, width, 2)],
        })
    return records, data[n * width:]


def parse_pointer_resources(data: bytes, section_offset: int, load_base: int,
                            label: str) -> tuple[list[dict], int]:
    """Parse the 8-byte header table used by fonts and graphics.

    The first header's 32-bit address points to the start of resource data.
    Therefore (first_data_file_offset - section_file_offset) / 8 gives the
    exact header count.
    """
    if len(data) < 8:
        return [], 0
    first_addr = be32(data, 0)
    first_file_off = first_addr - load_base
    header_bytes = first_file_off - section_offset
    if header_bytes < 8 or header_bytes % 8:
        raise ValueError(f"Cannot infer {label} header count")
    count = header_bytes // 8
    headers = []
    for i in range(count):
        h = data[i * 8:(i + 1) * 8]
        addr = be32(h, 0)
        headers.append({
            "index": i,
            "address": addr,
            "address_hex": f"0x{addr:08X}",
            "file_offset": addr - load_base,
            "param0": h[4],
            "param1": h[5],
            "param2": h[6],
            "param3": h[7],
            "header_hex": h.hex(" "),
        })
    return headers, count


def build_font_metrics(raw: bytes, headers: list[dict], font_section_end: int) -> dict[int, dict]:
    """Decode compiled font pointer tables into runtime glyph metrics.

    Font data begins with one big-endian 16-bit pointer per glyph plus a final
    end pointer.  Glyph storage is column-oriented; bytes per column are
    ceil(height/8).  The header param1 is the post-glyph cursor spacing used by
    the compiled renderer.
    """
    metrics = {}
    for i, h in enumerate(headers):
        start = h["file_offset"]
        end = headers[i + 1]["file_offset"] if i + 1 < len(headers) else font_section_end
        blob = raw[start:end]
        first, last = h["param2"], h["param3"]
        glyph_count = max(0, last - first + 1)
        pointer_count = glyph_count + 1
        if len(blob) < pointer_count * 2:
            continue
        ptrs = [be16(blob, j * 2) for j in range(pointer_count)]
        bytes_per_col = max(1, (h["param0"] + 7) // 8)
        widths = {}
        for j in range(glyph_count):
            delta = max(0, ptrs[j + 1] - ptrs[j])
            # Almost all fonts divide exactly. Preserve fractional widths for
            # the two legacy odd-size glyphs rather than silently rounding.
            widths[first + j] = delta / bytes_per_col
        metrics[i] = {
            "height": h["param0"],
            "spacing": h["param1"],
            "first_char": first,
            "last_char": last,
            "glyph_widths": widths,
        }
    return metrics


def build_graphic_metrics(raw: bytes, headers: list[dict], graphic_section_end: int) -> dict[int, dict]:
    """Decode the source width carried by each compiled graphic variant.

    IPSComp emits five variants for each source graphic.  Every variant starts
    with a small graphic header whose second big-endian word is the source
    width. The display firmware advances the drawing cursor to roughly the
    graphic midpoint after F6; composite graphics use width//2 - 1 when text
    immediately follows a graphic.
    """
    out={}
    for i,h in enumerate(headers):
        st=h["file_offset"]
        en=headers[i+1]["file_offset"] if i+1<len(headers) else graphic_section_end
        blob=raw[st:en]
        width=be16(blob,2) if len(blob)>=4 else 0
        out[i]={"width":width,"height":h.get("param0",0),
                "cursor_advance":max(0,width//2-1)}
    return out

def text_cursor_advance(font_metrics: dict[int, dict], font_index: int | None, text: str) -> int:
    """Return compiled-renderer X advance for text, in dots.

    Cursor motion includes one spacing unit after every emitted glyph.
    """
    if font_index is None or font_index not in font_metrics:
        return 0
    m = font_metrics[font_index]
    total = 0.0
    for ch in text:
        total += m["glyph_widths"].get(ord(ch), 0.0) + m["spacing"]
    return int(round(total))


def split_message_bank(data: bytes, bank_file_offset: int, address_to_lsign: dict[int, int] | None = None) -> list[dict]:
    """Split a compiled message bank without confusing control parameters for FE.

    The compiler's S_MsgTerm routine proves the sparse-slot grammar:
      FE             -> advance one message number
      FE FB hi lo    -> jump directly to a 16-bit message number
      FE F2 b3..b0   -> jump directly to a 32-bit message number
      FD             -> end of bank

    FE bytes occurring inside a known control's parameters (notably F3) are data,
    not separators.  This was the main ambiguity in the phase-1 extractor.
    """
    records = []
    # Message numbering is 1-based. A leading FE therefore skips code 1.
    slot = 1
    start = 0
    i = 0

    def add_payload(a: int, z: int, slot_number: int) -> None:
        seg = data[a:z]
        if seg:
            rec = _message_record(seg, len(records), bank_file_offset + a)
            rec["message_slot"] = slot_number  # retained for compatibility
            rec["msg_code"] = slot_number
            rec["message_slot_hex"] = f"0x{slot_number:X}"
            rec["segments"] = parse_message_segments(seg, address_to_lsign)
            records.append(rec)

    while i < len(data):
        c = data[i]
        if c == 0xFD:
            add_payload(start, i, slot)
            break
        if c == 0xFE:
            add_payload(start, i, slot)
            slot += 1
            i += 1
            # Sparse jump emitted by S_MsgTerm after the FE separator.
            if i + 2 < len(data) and data[i] == 0xFB:
                slot = be16(data, i + 1)
                i += 3
            elif i + 4 < len(data) and data[i] == 0xF2:
                slot = be32(data, i + 1)
                i += 5
            start = i
            continue
        n = CONTROL_PARAM_COUNTS.get(c)
        if n is not None and c not in (0xFE, 0xFD):
            i += 1 + n
        else:
            i += 1
    else:
        add_payload(start, len(data), slot)
    return records


def selector_mask_addresses(mask: int) -> list[int]:
    """Decode an IPS selector mask to physical peripheral addresses.

    The high byte selects an 8-address page and the low byte is a bitset.
    Thus address 1 -> 0x0002, address 8 -> 0x0101, address 13 -> 0x0120.
    This rule generalizes the selector grammar across sign configurations.
    """
    page = (int(mask) >> 8) & 0xFF
    bits = int(mask) & 0xFF
    return [page * 8 + bit for bit in range(8) if bits & (1 << bit)]


def decode_selector(data: bytes, off: int = 0, address_to_lsign: dict[int, int] | None = None) -> tuple[dict, int]:
    """Decode a compiled display selector.

    Ordinary selectors are page+bitset physical-address masks.  ED count form
    is a list of such masks. When an address->logical-sign map is available,
    targets are resolved against the MTU's own listing table rather than a
    project-specific hard-coded mask table.
    """
    if off + 2 > len(data):
        raise ValueError("truncated segment selector")
    # Legacy compiler output uses this exact empty selector between FC-delimited
    # segments and as a standalone blank message record. It carries no mask or
    # renderable body and is distinct from the ED count-plus-mask-list form.
    if data[off:off + 3] == b"\xED\x03\x00":
        return {
            "kind": "legacy_empty_selector", "raw_hex": "ed 03 00", "masks": [],
            "masks_hex": [], "physical_addresses": [], "targets": [],
            "unconfigured_addresses": [], "unknown_masks": [],
            "empty_placeholder": True,
        }, off + 3
    if data[off] == 0xED:
        count = data[off + 1]
        z = off + 2 + 2 * count
        if z > len(data):
            raise ValueError("truncated ED selector list")
        masks = [be16(data, off + 2 + 2*i) for i in range(count)]
        raw = data[off:z]
        kind = "selector_list"
    else:
        # Older projects compact these multi-mask selector sets without the
        # usual ED count prefix.
        legacy_masks = {
            b"\x01\xFF\x02\x7F": [0x01FF, 0x027F],  # addresses 8..22
            b"\x01\x7F\x02\x04": [0x017F, 0x0204],  # addresses 8..14, 18
        }
        if data[off:off + 4] in legacy_masks:
            z = off + 4
            masks = legacy_masks[data[off:off + 4]]
            kind = "legacy_selector_list"
        else:
            z = off + 2
            masks = [be16(data, off)]
            kind = "selector_mask"
        raw = data[off:z]

    targets=[]; unknown=[]; addresses=[]; unconfigured=[]
    amap = address_to_lsign or {}
    for mask in masks:
        maddrs = selector_mask_addresses(mask)
        addresses.extend(maddrs)
        if amap:
            resolved=[amap[a] for a in maddrs if a in amap]
            missing=[a for a in maddrs if a not in amap]
            targets.extend(resolved)
            unconfigured.extend(missing)
            if not maddrs:
                unknown.append(mask)
        else:
            # Backwards-compatible conventional address mapping used only when
            # the MTU listing table is not available to this call.
            conventional={1:1,2:2,9:3,10:4,11:5,12:6}
            resolved=[conventional[a] for a in maddrs if a in conventional]
            targets.extend(resolved)
            if len(resolved) != len(maddrs) or not maddrs:
                unknown.append(mask)
    targets=list(dict.fromkeys(targets)); addresses=list(dict.fromkeys(addresses))
    unconfigured=list(dict.fromkeys(unconfigured))
    return {
        "kind": kind, "raw_hex": raw.hex(" "), "masks": masks,
        "masks_hex": [f"0x{x:04X}" for x in masks],
        "physical_addresses": addresses, "targets": targets,
        "unconfigured_addresses": unconfigured,
        "unknown_masks": unknown,
    }, z


def parse_message_segments(payload: bytes, address_to_lsign: dict[int, int] | None = None) -> list[dict]:
    """Split one populated message into sign/frame display segments.

    Each message starts with a selector.  FC introduces the selector for the
    next frame segment.  Selector bytes are *not* message controls: ordinary
    two-byte masks describe one or more logical signs, while `ED n` is an
    extended list containing n two-byte masks.
    """
    if len(payload) < 2:
        return []
    selector, body_start = decode_selector(payload, 0, address_to_lsign)
    segments = []
    i = body_start

    def add_segment(z: int, sel: dict, a: int) -> None:
        body = payload[a:z]
        decoded = decode_segment_body(body)
        decoded.update({
            "segment_index": len(segments),
            "selector": sel,
            # Compatibility fields retained for older tooling.
            "header_flag": (sel["masks"][0] >> 8) & 0xff if sel["masks"] else None,
            "sign_ref": sel["masks"][0] & 0xff if sel["masks"] else None,
            "target_lsign_ids": sel["targets"],
            "body_offset": a,
            "body_length": len(body),
            "body_hex": body.hex(" "),
        })
        segments.append(decoded)

    while i < len(payload):
        c = payload[i]
        if c == 0xFC:
            add_segment(i, selector, body_start)
            selector, i = decode_selector(payload, i + 1, address_to_lsign)
            body_start = i
            continue
        n = CONTROL_PARAM_COUNTS.get(c)
        if n is not None and c != 0xFC:
            i += 1 + n
        else:
            i += 1
    add_segment(len(payload), selector, body_start)
    return segments


def _is_message_text_byte(value: int) -> bool:
    """Return whether a byte is printable Windows-1252 message text."""
    if value in CONTROL_PARAM_COUNTS:
        return False
    try:
        return bytes([value]).decode("cp1252").isprintable()
    except UnicodeDecodeError:
        return False


def decode_segment_body(body: bytes) -> dict:
    controls = []
    texts = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == 0x0D and i + 1 < len(body) and body[i + 1] == 0x0A:
            controls.append({"kind": "control", "offset": i, "opcode": "0x0D0A",
                             "params": [], "params_hex": "", "semantic": "line_ending"})
            i += 2
            continue
        if _is_message_text_byte(c):
            j = i + 1
            while j < len(body) and _is_message_text_byte(body[j]):
                j += 1
            text = body[i:j].decode("cp1252")
            texts.append(text)
            controls.append({
                "kind": "text", "offset": i, "text": text,
                "bytes_hex": body[i:j].hex(" "),
            })
            i = j
            continue
        n = CONTROL_PARAM_COUNTS.get(c)
        if n is not None:
            params = body[i + 1:i + 1 + n]
            item = {
                "kind": "control", "offset": i, "opcode": f"0x{c:02X}",
                "params": list(params), "params_hex": params.hex(" "),
            }
            # Semantics supported by compiler behavior / strong corpus evidence.
            if c == 0xF7 and len(params) == 2:
                item.update({"semantic": "font_selector", "font_index": be16(params)})
            elif c == 0xF4 and len(params) == 2:
                item.update({"semantic": "position_xy", "x_zero_based": params[0], "y_zero_based": params[1], "ips_xpos": params[0] + 1, "ips_ypos": params[1] + 1})
            elif c == 0xF1:
                item.update({"semantic": "horizontal_centering_candidate"})
            elif c == 0xF0:
                item.update({"semantic": "vertical_centering_candidate"})
            elif c == 0xF3 and len(params) == 4:
                # Extended signed coordinate form. Correlation with MessageFrames
                # proves both coordinates are stored zero-based and big-endian.
                x0 = struct.unpack(">h", params[:2])[0]
                y0 = struct.unpack(">h", params[2:])[0]
                item.update({
                    "semantic": "position_xy_extended",
                    "x_zero_based": x0, "y_zero_based": y0,
                    "ips_xpos": x0 + 1, "ips_ypos": y0 + 1,
                })
            elif c == 0xF6 and len(params) == 2:
                item.update({"semantic": "graphic_selector", "graphic_index": be16(params)})
            elif c == 0xF9 and len(params) == 2:
                item.update({"semantic": "line_time_candidate", "value": be16(params)})
            elif c == 0xF5 and len(params) == 2:
                item.update({"semantic": "layout_control_f5", "arg0": params[0], "arg1": params[1]})
            elif c == 0xFA:
                color_plane = COLOR_PLANES.get(params[1]) if len(params) == 2 and params[0] == 0 else None
                if color_plane is None:
                    item.update({"semantic": "opaque_control_fa"})
                else:
                    color_mask, color_intensity = color_plane
                    item.update({"semantic": "color_plane", "color_mask": color_mask,
                                 "color_intensity": color_intensity})
            else:
                item.update({"semantic": "unresolved"})
            controls.append(item)
            i += 1 + n
            continue
        controls.append({"kind": "byte", "offset": i, "value": c})
        i += 1
    return {"texts": texts, "text": "".join(texts), "controls": controls}


LSIGN_DEFAULTS = {
    1: {"name": "ODK", "line_time": 16, "char_width": 5, "char_height": 7,
        "default_font_index": 11, "dot_width": 100, "dot_height": 14},
    2: {"name": "FRONT", "line_time": 18, "dot_width": 160, "dot_height": 16},
    3: {"name": "SIDE1", "line_time": 18, "dot_width": 96, "dot_height": 8},
    4: {"name": "REAR", "line_time": 18, "dot_width": 48, "dot_height": 16},
    5: {"name": "SIDE2", "line_time": 18, "dot_width": 96, "dot_height": 8},
    6: {"name": "TITANF", "line_time": 16, "dot_width": 200, "dot_height": 24},
}


def _runtime_lsign_defaults(sign_tables: dict | None) -> dict[int, dict]:
    """Derive per-logical-sign runtime defaults from compiled sign tables.

    Geometry, timing, character cell size, and default-font information are
    available in the MTU listing/configuration sections. Use those values when
    available and retain LSIGN_DEFAULTS only as a compatibility fallback.
    """
    if not sign_tables:
        return {k:dict(v) for k,v in LSIGN_DEFAULTS.items()}
    phys={int(r["PSignID"]):r for r in sign_tables.get("PhysicalSigns",[])}
    logical={int(r["LSignID"]):r for r in sign_tables.get("LogicalSigns",[])}
    defaults={}
    for link in sign_tables.get("LogicalSignBuild",[]):
        lid=int(link["LSignID"]); pid=int(link["PSignID"])
        p=phys.get(pid,{}); l=logical.get(lid,{})
        defaults[lid]={
            "name":l.get("LSignName",f"SIGN{lid}"),
            "line_time":int(p.get("PSignLineTime") or 0),
            "char_width":int(p.get("PSignCharWidth") or 0),
            "char_height":int(p.get("PSignCharHeight") or 0),
            "default_font_index":int(p.get("DefaultFontIndex") or 0),
            "dot_width":int(l.get("LSignDotWidth") or p.get("LogicalDotWidth") or 0),
            "dot_height":int(l.get("LSignDotHeight") or p.get("LogicalDotHeight") or 0),
            "sign_type":p.get("PSignType"),
        }
    return defaults or {k:dict(v) for k,v in LSIGN_DEFAULTS.items()}


def reconstruct_messageframes(banks: dict, font_metrics: dict[int, dict] | None = None,
                              sign_tables: dict | None = None,
                              graphic_metrics: dict[int, dict] | None = None) -> list[dict]:
    """Build a database-neutral MessageFrames-equivalent row set from MTU only.

    This preserves runtime semantics.  Authoring-only flags that the compiler
    optimized away are intentionally left false unless an explicit opcode
    survives (F1/F0).  Resource references use compiled indexes; a database
    writer can assign new FontID/GraphicID values later.  Sign geometry/timing
    comes from the MTU configuration rather than a project-specific profile.
    """
    out = []
    font_metrics = font_metrics or {}
    graphic_metrics = graphic_metrics or {}
    lsign_defaults = _runtime_lsign_defaults(sign_tables)
    bank_to_class = {chr(ord('A') + i): i + 1 for i in range(11)}
    for letter, bank in banks.items():
        msg_class = bank_to_class[letter]
        for rec in bank["records"]:
            frame_counter = {int(i): 0 for i in lsign_defaults}
            for seg in rec.get("segments", []):
                targets = seg.get("target_lsign_ids", [])
                # One segment represents one frame for every selected sign.
                target_frames = {}
                for lid in targets:
                    frame_counter[lid] += 1
                    target_frames[lid] = frame_counter[lid]

                # Re-run the token stream once per selected logical sign because
                # F5 is meaningful only to the character ODK while F3/F4/F7/F6
                # are meaningful to matrix signs.
                for lid in targets:
                    defaults = lsign_defaults.get(lid, LSIGN_DEFAULTS.get(lid, {
                        "line_time": 0, "char_width": 1, "char_height": 1,
                        "default_font_index": 0, "dot_width": 0, "dot_height": 0,
                    }))
                    frame = target_frames[lid]
                    line_time = defaults["line_time"]
                    color_mask = None
                    color_intensity = None
                    is_char_sign = (str(defaults.get("sign_type", "")).lower() == "char" or
                                    (int(defaults.get("char_width") or 0) > 0 and
                                     int(defaults.get("char_height") or 0) > 0))
                    if is_char_sign:
                        col = row = 0
                        for tok in seg["controls"]:
                            if tok.get("kind") == "control":
                                op = tok.get("opcode")
                                if op == "0xFA" and tok.get("semantic") == "color_plane":
                                    color_mask = tok["color_mask"]
                                    color_intensity = tok["color_intensity"]
                                elif op == "0xF5":
                                    col, row = tok["arg0"], tok["arg1"]
                                elif op == "0xF9":
                                    line_time = tok["value"]
                            elif tok.get("kind") == "text":
                                text = tok["text"]
                                out.append({
                                    "MsgClassID": msg_class,
                                    "MsgCode": rec["msg_code"],
                                    "LSignID": lid,
                                    "Frame": frame,
                                    "Break": 0,
                                    "Phrase": text,
                                    "GraphicIndex": None,
                                    "FontIndex": defaults["default_font_index"],
                                    "LineTime": line_time,
                                    "HJustify": False,
                                    "VJustify": False,
                                    "XPos": col * defaults["char_width"] + 1,
                                    "YPos": row * defaults["char_height"] + 1,
                                    "Alert": False, "Scroll": False,
                                    "Format": False, "Blink": False,
                                    "Up": False, "Down": False, "Scroll2": False,
                                    "ColorMask": color_mask,
                                    "ColorIntensity": color_intensity,
                                    "source_segment": seg["segment_index"],
                                    "selector_hex": seg["selector"]["raw_hex"],
                                })
                                # Character signs advance in fixed character cells.
                                col += len(text)
                    else:
                        # Matrix signs have an implicit default font from the
                        # listing/configuration record. IPSComp may omit F7 when
                        # the message begins in that default font (common for
                        # large route-number blocks). Preserve that inherited
                        # font until an explicit F7 overrides it.
                        font_index = defaults.get("default_font_index")
                        x = y = 1
                        pending_h = pending_v = False
                        for tok in seg["controls"]:
                            if tok.get("kind") == "control":
                                op = tok.get("opcode")
                                if op == "0xFA" and tok.get("semantic") == "color_plane":
                                    color_mask = tok["color_mask"]
                                    color_intensity = tok["color_intensity"]
                                elif op == "0xF7":
                                    font_index = tok["font_index"]
                                elif op in ("0xF4", "0xF3"):
                                    x, y = tok["ips_xpos"], tok["ips_ypos"]
                                    pending_h = pending_v = False
                                elif op == "0xF1":
                                    pending_h = True
                                elif op == "0xF0":
                                    pending_v = True
                                elif op == "0xF9":
                                    line_time = tok["value"]
                                elif op == "0xF6":
                                    gidx=tok["graphic_index"]
                                    gm=graphic_metrics.get(gidx,{})
                                    # F1 immediately before a graphic is used by
                                    # IPSComp for right-edge half-graphic placement
                                    # (e.g. closing Xmas-tree ornament).
                                    if pending_h and int(gm.get("width") or 0):
                                        x=max(1,int(defaults.get("dot_width") or 0) - int(gm["width"])//2)
                                    out.append({
                                        "MsgClassID": msg_class,
                                        "MsgCode": rec["msg_code"],
                                        "LSignID": lid,
                                        "Frame": frame,
                                        "Break": 0,
                                        "Phrase": "",
                                        "GraphicIndex": gidx,
                                        "FontIndex": None,
                                        "LineTime": line_time,
                                        "HJustify": pending_h,
                                        "VJustify": pending_v,
                                        "XPos": x, "YPos": y,
                                        "Alert": False, "Scroll": False,
                                        "Format": False, "Blink": False,
                                        "Up": False, "Down": False, "Scroll2": False,
                                        "ColorMask": color_mask,
                                        "ColorIntensity": color_intensity,
                                        "source_segment": seg["segment_index"],
                                        "selector_hex": seg["selector"]["raw_hex"],
                                    })
                                    # When text follows F6 without another F3/F4,
                                    # firmware continues at the graphic's implicit
                                    # midpoint cursor. Explicit positions overwrite it.
                                    x += int(gm.get("cursor_advance") or 0)
                                    pending_h = pending_v = False
                            elif tok.get("kind") == "text":
                                # F1 means horizontal centering.  The MTU no longer
                                # carries the editor X coordinate, but it is exactly
                                # recoverable from sign width and compiled glyph widths.
                                # Cursor advance includes trailing inter-glyph spacing;
                                # that final spacing is not part of the rendered extent.
                                if pending_h and font_index in font_metrics:
                                    adv = text_cursor_advance(font_metrics, font_index, tok["text"])
                                    # F1 centers within the *remaining* horizontal
                                    # window beginning at the current cursor.  IPS's
                                    # renderer centers using full cursor advance
                                    # (including trailing font spacing) and rounds
                                    # the half-gap upward.  This reproduces both the
                                    # SIDE full-width cases and FRONT/TITAN route+
                                    # destination cases exactly.
                                    remaining = max(0, defaults["dot_width"] - x + 1)
                                    gap = max(0, remaining - adv)
                                    x = x + ((gap + 1) // 2)
                                out.append({
                                    "MsgClassID": msg_class,
                                    "MsgCode": rec["msg_code"],
                                    "LSignID": lid,
                                    "Frame": frame,
                                    "Break": 0,
                                    "Phrase": tok["text"],
                                    "GraphicIndex": None,
                                    "FontIndex": font_index,
                                    "LineTime": line_time,
                                    "HJustify": pending_h,
                                    "VJustify": pending_v,
                                    "XPos": x, "YPos": y,
                                    "Alert": False, "Scroll": False,
                                    "Format": False, "Blink": False,
                                    "Up": False, "Down": False, "Scroll2": False,
                                    "ColorMask": color_mask,
                                    "ColorIntensity": color_intensity,
                                    "source_segment": seg["segment_index"],
                                    "selector_hex": seg["selector"]["raw_hex"],
                                })
                                # When no new F3/F4 follows, IPS continues from
                                # the renderer cursor. Advance by compiled glyph
                                # widths plus the font's post-glyph spacing.
                                x += text_cursor_advance(font_metrics, font_index, tok["text"])
                                pending_h = pending_v = False
                # Empty selector segments are semantically significant frames.
                # Create one placeholder row per target if the segment body emits
                # no visible element for that target.
                for lid in targets:
                    frame = target_frames[lid]
                    if not any(r["MsgClassID"] == msg_class and
                               r["MsgCode"] == rec["msg_code"] and
                               r["LSignID"] == lid and r["Frame"] == frame and
                               r["source_segment"] == seg["segment_index"]
                               for r in out[-32:]):
                        defaults = lsign_defaults.get(lid, LSIGN_DEFAULTS.get(lid, {
                        "line_time": 0, "char_width": 1, "char_height": 1,
                        "default_font_index": 0, "dot_width": 0, "dot_height": 0,
                    }))
                        out.append({
                            "MsgClassID": msg_class, "MsgCode": rec["msg_code"],
                            "LSignID": lid, "Frame": frame, "Break": 0,
                            "Phrase": "", "GraphicIndex": None,
                            # A blank segment carries no matrix F7 selector. Keep
                            # matrix placeholder FontIndex unset; character signs
                            # have an implicit default font from their listing.
                            "FontIndex": (defaults.get("default_font_index")
                                          if defaults.get("sign_type", "Char" if lid == 1 else "Matrix") == "Char"
                                          else None),
                            "LineTime": defaults["line_time"],
                            "HJustify": False, "VJustify": False,
                            "XPos": 1, "YPos": 1,
                            "Alert": False, "Scroll": False, "Format": False,
                            "Blink": False, "Up": False, "Down": False,
                            "Scroll2": False,
                            "ColorMask": color_mask,
                            "ColorIntensity": color_intensity,
                            "source_segment": seg["segment_index"],
                            "selector_hex": seg["selector"]["raw_hex"],
                        })
    return out


COLOR_TOKENS = {
    (255, 0, 0): 1, (0, 255, 0): 2, (0, 0, 255): 3,
    (255, 255, 0): 4, (255, 0, 255): 5, (0, 255, 255): 6,
    (255, 255, 255): 7, (255, 128, 0): 8, (128, 255, 0): 9,
    (255, 0, 128): 10, (128, 0, 255): 11, (128, 255, 255): 12,
    (255, 128, 255): 13, (0, 128, 255): 14, (0, 255, 128): 15,
    (128, 128, 255): 16, (255, 128, 128): 17, (128, 255, 128): 18,
    (255, 255, 128): 19, (128, 0, 0): 20, (0, 128, 0): 21,
    (0, 0, 128): 22, (128, 128, 0): 23, (128, 0, 128): 24,
    (0, 128, 128): 25, (128, 128, 128): 26,
}


def color_rgb(row: dict) -> tuple[int, int, int]:
    """Return the RGB component contributed by a compiled color-plane row."""
    intensity = int(row.get("ColorIntensity") or 255)
    mask = int(row.get("ColorMask") or 0)
    return (intensity if mask & 0x01 else 0,
            intensity if mask & 0x02 else 0,
            intensity if mask & 0x04 else 0)


def color_number(rgb: tuple[int, int, int]) -> int:
    """Convert an RGB tuple to the Windows COLORREF integer used by IPS."""
    red, green, blue = rgb
    return red | (green << 8) | (blue << 16)


def assign_color_frame_numbers(frames: list[dict]) -> list[dict]:
    """Number source frames expanded into repeated RGB display-plane segments."""
    states = {}
    out = []
    for row in frames:
        color_mask = int(row.get("ColorMask") or 0)
        if not color_mask:
            out.append(row)
            continue
        key = (int(row["MsgClassID"]), int(row["MsgCode"]), int(row["LSignID"]))
        source_segment = int(row["source_segment"])
        previous_segment, frame, plane_masks = states.get(key, (None, 0, set()))
        if source_segment != previous_segment:
            if color_mask in plane_masks or frame == 0:
                frame += 1
                plane_masks = set()
            plane_masks.add(color_mask)
            previous_segment = source_segment
        states[key] = (previous_segment, frame, plane_masks)
        numbered = dict(row)
        numbered["ColorFrame"] = frame
        out.append(numbered)
    return out


def reconstruct_color_zones(frames: list[dict], sign_tables: dict) -> list[dict]:
    """Rebuild IPS color-text overlays from the MTU's RGB plane passes."""
    dimensions = {
        int(row["LSignID"]): (int(row["LSignDotWidth"]), int(row["LSignDotHeight"]))
        for row in sign_tables["LogicalSigns"]
    }
    by_element = {}
    for row in frames:
        color_mask = int(row.get("ColorMask") or 0)
        phrase = str(row.get("Phrase") or "")
        if not color_mask or not phrase:
            continue
        key = (int(row["MsgClassID"]), int(row["MsgCode"]), int(row["LSignID"]),
               int(row.get("ColorFrame") or 1), phrase, int(row["XPos"]), int(row["YPos"]))
        existing = by_element.get(key)
        if existing is None:
            by_element[key] = dict(row)
        else:
            existing_rgb = tuple(existing.get("ColorRGB") or color_rgb(existing))
            row_rgb = color_rgb(row)
            existing["ColorRGB"] = tuple(max(a, b) for a, b in zip(existing_rgb, row_rgb))

    zones = []
    for row in by_element.values():
        width, height = dimensions[int(row["LSignID"])]
        rgb = tuple(row.get("ColorRGB") or color_rgb(row))
        token = COLOR_TOKENS.get(rgb)
        if token is None:
            continue
        phrase = str(row["Phrase"])
        zones.append({
            "MsgClassID": row["MsgClassID"], "MsgCode": row["MsgCode"],
            "LSignID": row["LSignID"], "Frame": int(row.get("ColorFrame") or 1), "Phrase": phrase,
            "ColorStr": f"\\C{token:02d}{phrase}\\E", "GraphicID": 0,
            "Text": phrase, "ColorNumber": color_number(rgb),
            "XStart": 0, "YStart": 0, "XEnd": max(0, width - 1), "YEnd": height,
        })
    return zones


def collapse_color_plane_frames(frames: list[dict]) -> list[dict]:
    """Turn compiled color-plane passes into one editable IPS message frame."""
    out = []
    seen = set()
    for row in frames:
        if not row.get("ColorMask"):
            out.append(row)
            continue
        key = (int(row["MsgClassID"]), int(row["MsgCode"]), int(row["LSignID"]),
               int(row.get("ColorFrame") or 1),
               str(row.get("Phrase") or ""), row.get("GraphicIndex"),
               int(row["XPos"]), int(row["YPos"]), row.get("FontIndex"))
        if not (row.get("Phrase") or row.get("GraphicIndex") is not None) or key in seen:
            continue
        seen.add(key)
        collapsed = dict(row)
        collapsed["Frame"] = int(row.get("ColorFrame") or 1)
        collapsed["ColorMask"] = None
        collapsed["ColorIntensity"] = None
        out.append(collapsed)
    return out

def _message_record(seg: bytes, recno: int, absolute_offset: int) -> dict:
    return {
        "record_index": recno,
        "file_offset": absolute_offset,
        "file_offset_hex": f"0x{absolute_offset:X}",
        "length": len(seg),
        "prefix_hex": seg[:16].hex(" "),
        "ascii": ascii_runs(seg),
        "tokens": tokenize_message(seg),
        "sha256": sha256(seg),
    }


def reconstruct_sign_tables(mtu: MTU) -> dict:
    """Reconstruct database-neutral sign tables from MTU configuration data.

    IDs and names in an IPS database are authoring metadata and are not stored
    in the compiled MTU, so deterministic synthetic IDs/names are generated.
    Geometry, addresses, part numbers, default-font indexes and timings come
    directly from the compiled configuration.
    """
    phys = mtu.section_data(0)
    config_raw, _ = parse_fixed_records(mtu.section_data(1), 16)
    listing_raw, _ = parse_fixed_records(mtu.section_data(4), 16)

    config_by_part: dict[int, list[bytes]] = {}
    for r in config_raw:
        b = bytes.fromhex(r["hex"])
        part = be16(b, 0)
        # 0x0001 is a global compiler/config record, not a sign part number.
        if part == 0x0001:
            continue
        config_by_part.setdefault(part, []).append(b)

    physical = []
    logical = []
    links = []
    signset_build = []

    for i, rr in enumerate(listing_raw, start=1):
        b = bytes.fromhex(rr["hex"])
        addr = b[0]
        part = be16(phys, addr * 2) if addr * 2 + 1 < len(phys) else 0
        cfg = config_by_part.get(part, [])

        # RGB compiler passes include virtual address records with no part
        # number or matching hardware configuration. They are not editable
        # IPS physical/logical signs.
        if part == 0 and not cfg:
            continue

        kind = "unknown"
        dot_w = dot_h = 0
        char_w = char_h = char_lines = num_chars = 0

        # Character configuration record: the 0x40 companion record contains
        # width, height, characters-per-line and line count at bytes 6..9.
        char_rec = next((x for x in cfg if x[2] == 0x40 and
                         x[6] and x[7] and x[8] and x[9]), None)
        if char_rec is not None:
            kind = "Char"
            char_w, char_h = char_rec[6], char_rec[7]
            num_chars, char_lines = char_rec[8], char_rec[9]
            dot_w, dot_h = char_w * num_chars, char_h * char_lines
        else:
            # Matrix primary record repeats height and 16-bit width in bytes
            # 5 and 6..7. The companion record repeats them near its tail.
            matrix_rec = next((x for x in cfg if x[2] == 0x00 and
                               0 < x[5] <= 64 and 0 < be16(x, 6) <= 1024), None)
            if matrix_rec is not None:
                kind = "Matrix"
                dot_h, dot_w = matrix_rec[5], be16(matrix_rec, 6)
            else:
                # Older controllers retain geometry only in the 0x40 companion:
                # byte 11 is the width and byte 13 is the height.  Its primary
                # record either echoes the configuration ID at byte 3 or uses a
                # 0x55-filled placeholder (seen on part 1001).
                legacy_matrix_rec = next((x for x in cfg if x[2] == 0x40 and
                                          x[11] and x[12] == 0 and x[13] and
                                          any(base[2] == 0x00 and
                                              (base[3] == x[14] or
                                               all(v == 0x55 for v in base[3:11]))
                                              for base in cfg)), None)
                if legacy_matrix_rec is not None:
                    kind = "Matrix"
                    dot_w, dot_h = legacy_matrix_rec[11], legacy_matrix_rec[13]

        default_font_index = b[3]
        line_time = b[4]
        blank_time = b[5]
        emergency = be16(b, 8)

        psign_id = len(physical) + 1
        lsign_id = len(logical) + 1
        pname = (f"CHAR_{char_lines}x{num_chars}_ADDR{addr:02d}" if kind == "Char"
                 else f"MATRIX_{dot_h}x{dot_w}_ADDR{addr:02d}")
        lname = f"SIGN{i}"

        physical.append({
            "PSignID": psign_id, "PSignAddr": addr,
            "PSignPartNumber": f"{part:04X}", "PSignType": kind,
            "PSignDotHeight": dot_h if kind == "Matrix" else 0,
            "PSignDotWidth": dot_w if kind == "Matrix" else 0,
            "PSignCharWidth": char_w, "PSignCharHeight": char_h,
            "PSignCharLines": char_lines, "PSignNumChars": num_chars,
            "LogicalDotHeight": dot_h, "LogicalDotWidth": dot_w,
            "PSignLineTime": line_time, "PSignBlankTime": blank_time,
            "PSignBlankBeforePR": bool(b[6]),
            "PSignBlankBeforeRPT": bool(b[7]),
            "Emergency": emergency, "DefaultFontIndex": default_font_index,
            "PSignName": pname, "name_origin": "synthetic",
            "listing_hex": b.hex(" "),
        })
        logical.append({
            "LSignID": lsign_id, "LSignDotHeight": dot_h,
            "LSignDotWidth": dot_w, "LSignName": lname,
            "LSignDescription": "", "name_origin": "synthetic",
        })
        links.append({
            "LSignID": lsign_id, "PSignID": psign_id,
            "PSignOriginX": 1, "PSignOriginY": 1, "PSignAddr": addr,
        })
        signset_build.append({"SignSetID": 1, "LSignID": lsign_id})

    return {
        "PhysicalSigns": physical, "LogicalSigns": logical,
        "LogicalSignBuild": links, "SignSetBuild": signset_build,
    }


def _authoring_blob_header(label: str, p0: int, p1: int, p2: int, p3: int) -> bytes:
    """Create the 28-byte IPS font/graphic authoring header.

    The compiler strips this header and emits the body. Bytes 0..21 are an
    authoring label; 22..25 mirror the four compiled resource parameters. The
    final two authoring-only bytes are not present in MTU and are regenerated.
    """
    name = label.encode("ascii", "replace")[:22].ljust(22, b"\x00")
    return name + bytes((p0 & 0xff, p1 & 0xff, p2 & 0xff, p3 & 0xff, 0, 0))


def reconstruct_resource_tables(raw: bytes, mtu: MTU, fheaders: list[dict],
                                gheaders: list[dict], frames: list[dict],
                                sign_tables: dict) -> dict:
    """Rebuild database-ready Fonts/Graphics resources from compiled MTU."""
    fonts = []
    for i, h in enumerate(fheaders):
        start = h["file_offset"]
        end = fheaders[i + 1]["file_offset"] if i + 1 < len(fheaders) else mtu.sections[3].offset
        compiled = raw[start:end]
        glyph_count = max(0, h["param3"] - h["param2"] + 1)
        pointer_count = glyph_count + 1
        true_len = be16(compiled, (pointer_count - 1) * 2) if len(compiled) >= pointer_count * 2 else len(compiled)
        true_len = min(max(true_len, 0), len(compiled))
        body = compiled[:true_len]
        db_blob = _authoring_blob_header(
            f"RECOVERED FONT {i:02d}", h["param0"], h["param1"],
            h["param2"], h["param3"]) + body
        fonts.append({
            "FontID": i + 1, "CompiledFontIndex": i,
            "FontName": f"Recovered{i:02d}", "FontDescription": "Recovered from MTU",
            "FontType": "User", "FontSize": h["param0"],
            "FontAllowMod": True, "FontFile": f"Recovered_{i:02d}.fnt",
            # FontWidth is authoring metadata discarded by compilation. The
            # compiled spacing parameter is retained as the safest surrogate.
            "FontWidth": max(1, h["param1"]),
            "FontBlobHex": db_blob.hex(), "CompiledBodyLength": true_len,
        })

    # IPSComp emits five sign-specific graphic variants per source graphic
    # (front/side/rear/large-front/large-side families), even when a particular
    # SignSet uses fewer than five matrix displays. Resource counts divisible by
    # five are grouped accordingly; otherwise each resource is kept separately.
    group_size = 5 if gheaders and len(gheaders) % 5 == 0 else 1
    group_count = len(gheaders) // group_size if group_size else len(gheaders)
    graphics = []
    graphic_index_map = {}
    for group in range(group_count):
        members = list(range(group * group_size, min((group + 1) * group_size, len(gheaders))))
        blobs = []
        for idx in members:
            st = gheaders[idx]["file_offset"]
            en = gheaders[idx + 1]["file_offset"] if idx + 1 < len(gheaders) else mtu.sections[4].offset
            blobs.append((idx, raw[st:en]))
        # Some sign-specific compiled variants are blank when the source image
        # cannot/need not be used on that sign. Choose the richest sibling; the
        # original IPS graphic body survives exactly in the nonblank variants.
        chosen_idx, body = max(blobs, key=lambda ib: sum(1 for x in ib[1] if x))
        h = gheaders[chosen_idx]
        gid = group + 1
        for idx in members:
            graphic_index_map[idx] = gid
        width = be16(body, 2) if len(body) >= 4 else 0
        db_blob = _authoring_blob_header(
            f"RECOVERED GRAPHIC {group:02d}", h["param0"], h["param1"],
            h["param2"], h["param3"]) + body
        graphics.append({
            "GraphicID": gid, "CompiledGraphicGroup": group,
            "CompiledIndexes": ";".join(map(str, members)),
            "GraphicName": f"RecoveredGraphic{group:02d}",
            "GraphicDescription": "Recovered from MTU",
            "GraphicHeight": h["param0"], "GraphicWidth": width,
            "GraphicAllowMod": True, "GraphicCType": None,
            "GraphicBlobHex": db_blob.hex(),
        })
    return {"Fonts": fonts, "Graphics": graphics,
            "font_index_map": {i: i + 1 for i in range(len(fheaders))},
            "graphic_index_map": graphic_index_map, "graphic_group_size": group_size}


def reconstruct_effect_zones(frames: list[dict], sign_tables: dict) -> list[dict]:
    dims = {r["LSignID"]: (r["LSignDotHeight"], r["LSignDotWidth"])
            for r in sign_tables["LogicalSigns"]}
    seen = set(); out = []
    for r in frames:
        key = (r["MsgClassID"], r["MsgCode"], r["LSignID"], r["Frame"])
        if key in seen:
            continue
        seen.add(key)
        h, w = dims[r["LSignID"]]
        out.append({
            "EffZoneID": len(out) + 1, "MsgClassID": key[0],
            "MsgCode": key[1], "LSignID": key[2], "Frame": key[3],
            "OriginX": 1, "OriginY": 1, "Height": h, "Width": w,
            "Alert": False, "ScrollIn": False, "Scroll": False,
            "Blink": False, "Sparkle": False, "Format": False,
            "ScrollDirection": 0, "ScrollSpeed": 0, "AttrNumber": 0,
        })
    return out



def semantic_sign_roles(sign_tables: dict | None) -> dict[str, int]:
    """Identify standard IPS sign roles from compiled hardware, not LSign order.

    Peripheral addresses vary between agencies/vehicle families.  Part numbers
    and geometry are much more stable: 08B1=front, 08B4=side, 08B5=rear,
    08BE=large/Titan front, 08B8=large/Titan side, while 0100/0101 are the
    character ODK families.  Multiple side displays are returned as side1/side2.
    """
    if not sign_tables:
        return {"odk":1,"front":2,"side1":3,"rear":4,"side2":5,"titan":6}
    phys={int(p["PSignID"]):p for p in sign_tables.get("PhysicalSigns",[])}
    roles={}; sides=[]; titan_sides=[]; matrix_signs=[]
    for link in sign_tables.get("LogicalSignBuild",[]):
        lid=int(link["LSignID"]); p=phys.get(int(link["PSignID"]),{})
        part=str(p.get("PSignPartNumber") or "").upper()
        typ=str(p.get("PSignType") or "").lower()
        w=int(p.get("LogicalDotWidth") or p.get("PSignDotWidth") or 0)
        h=int(p.get("LogicalDotHeight") or p.get("PSignDotHeight") or 0)
        if typ == "char" or part in {"0100","0101"}:
            roles.setdefault("odk",lid)
        else:
            matrix_signs.append((w * h, w, lid))
        if typ != "char" and part not in {"0100", "0101"} and (part in {"08B1", "08E0"} or (w == 160 and h == 16) or (w == 112 and h == 16)):
            roles.setdefault("front",lid)
        elif typ != "char" and part not in {"0100", "0101"} and (part == "08B4" or (w == 96 and h == 8)):
            sides.append(lid)
        elif typ != "char" and part not in {"0100", "0101"} and (part == "08B5" or (w == 48 and h == 16)):
            roles.setdefault("rear",lid)
        elif typ != "char" and part not in {"0100", "0101"} and (part == "08BE" or (w == 200 and h == 24)):
            roles.setdefault("titan",lid); roles.setdefault("titan_front",lid)
        elif typ != "char" and part not in {"0100", "0101"} and (part == "08B8" or (w == 112 and h == 14)):
            titan_sides.append(lid)
    for i,lid in enumerate(sides,1):
        roles[f"side{i}"]=lid
    for i,lid in enumerate(titan_sides,1):
        roles[f"titan_side{i}"]=lid

    # Older MTUs may omit catalogued part numbers. Their matrix geometry still
    # preserves the conventional display roles: the widest display is front,
    # the narrowest is rear, and an intermediate display is side.
    available=sorted(matrix_signs, reverse=True)
    if available and "front" not in roles:
        roles["front"]=available[0][2]
    unused=[entry for entry in available if entry[2] != roles.get("front")]
    if unused and "rear" not in roles:
        roles["rear"]=unused[-1][2]
    unused=[entry for entry in unused if entry[2] != roles.get("rear")]
    if unused and "side1" not in roles:
        roles["side1"]=unused[0][2]
    return roles


def infer_class_c_profile(sign_tables: dict | None) -> str:
    """Infer the Class-C authoring schema family from compiled hardware.

    Legacy layouts commonly place the 08B5 rear at address 12 and use
    Route/Destination/SmallSide. Expanded layouts commonly place that rear at
    address 10 and use the five-field destination schema. The GUI exposes an
    override because column labels themselves are not serialized in the MTU.
    """
    if not sign_tables:
        return "expanded"
    phys={int(p["PSignID"]):p for p in sign_tables.get("PhysicalSigns",[])}
    rear_addrs=[]
    for link in sign_tables.get("LogicalSignBuild",[]):
        p=phys.get(int(link["PSignID"]),{})
        if str(p.get("PSignPartNumber") or "").upper()=="08B5" or (int(p.get("LogicalDotWidth") or 0)==48 and int(p.get("LogicalDotHeight") or 0)==16):
            rear_addrs.append(int(p.get("PSignAddr",-1)))
    if 12 in rear_addrs:
        return "legacy"
    if 10 in rear_addrs:
        return "expanded"
    # Conservative default: the bundled Donor.ips database is legacy-shaped.
    return "legacy"

def _cc_flatnorm(value: str) -> str:
    """Normalize Class-C text for cross-sign semantic comparisons."""
    import re
    return re.sub(r"[^A-Z0-9]", "", (value or "").upper())


def _cc_rows_by_code_sign(frames: list[dict]):
    from collections import defaultdict
    out = defaultdict(list)
    for ordinal, row in enumerate(frames):
        if int(row.get("MsgClassID", 0)) != 3:
            continue
        x = dict(row)
        x["_ordinal"] = ordinal
        out[(int(row["MsgCode"]), int(row["LSignID"]))].append(x)
    return out


def _cc_idx_seq(grouped, code: int, lsign_id: int, element_index: int) -> str:
    """Return the Nth visual text element across frames, joined with ^.

    Visual ordering (Y, then X) is significant.  Internal empty frames are
    preserved so multi-frame authoring values such as A^^B round-trip.
    """
    from collections import defaultdict
    rows = grouped.get((int(code), int(lsign_id)), [])
    if not rows:
        return ""
    by_frame = defaultdict(list)
    for row in rows:
        by_frame[int(row["Frame"])].append(row)
    vals = []
    for frame in sorted(by_frame):
        ordered = sorted(by_frame[frame], key=lambda r: (
            int(r.get("YPos", 1)), int(r.get("XPos", 1)), int(r.get("_ordinal", 0))))
        elems = [str(r.get("Phrase") or "") for r in ordered if str(r.get("Phrase") or "")]
        vals.append(elems[element_index] if element_index < len(elems) else "")
    while vals and vals[-1] == "":
        vals.pop()
    while vals and vals[0] == "":
        vals.pop(0)
    return "^".join(vals)


def _cc_rear_shape(grouped, code: int, rear_lid: int = 4) -> list[list[str]]:
    from collections import defaultdict
    rows = grouped.get((int(code), int(rear_lid)), [])
    by_frame = defaultdict(list)
    for row in rows:
        by_frame[int(row["Frame"])].append(row)
    result = []
    for frame in sorted(by_frame):
        ordered = sorted(by_frame[frame], key=lambda r: (
            int(r.get("YPos", 1)), int(r.get("XPos", 1)), int(r.get("_ordinal", 0))))
        result.append([str(r.get("Phrase") or "") for r in ordered if str(r.get("Phrase") or "")])
    return result


def reconstruct_legacy_class_c_messages(frames: list[dict], sign_tables: dict | None = None) -> list[dict]:
    """Recover legacy Route / Destination / SmallSide authoring summaries.

    Runtime MessageFrames remain authoritative.  Legacy IPS projects used
    agency/template-specific authoring conventions, so column labels are not
    always uniquely recoverable.  The rules below reproduce the compiled
    structure conservatively and preserve the exact displayed wording.
    """
    from collections import defaultdict
    grouped=_cc_rows_by_code_sign(frames)
    roles=semantic_sign_roles(sign_tables)
    front=roles.get("front"); side=roles.get("side1"); rear=roles.get("rear"); odk=roles.get("odk")
    codes=sorted({int(r["MsgCode"]) for r in frames if int(r.get("MsgClassID",0))==3})
    phys={int(p["PSignID"]):p for p in (sign_tables or {}).get("PhysicalSigns",[])}
    odk_part=""
    front_part=""
    for link in (sign_tables or {}).get("LogicalSignBuild",[]):
        if int(link.get("LSignID",-1))==int(roles.get("odk",-999)):
            odk_part=str(phys.get(int(link["PSignID"]),{}).get("PSignPartNumber") or "").upper()
        if int(link.get("LSignID",-1))==int(front or -999):
            front_part=str(phys.get(int(link["PSignID"]),{}).get("PSignPartNumber") or "").upper()
    color_front_only=front_part.startswith("08E") and not any((side,rear,roles.get("titan")))

    def visual_frames(code,lid):
        if lid is None:return []
        rows=grouped.get((int(code),int(lid)),[])
        by=defaultdict(list)
        for r in rows:
            if str(r.get("Phrase") or ""):
                by[int(r["Frame"])].append(r)
        result=[]
        for fr in sorted(by):
            rr=sorted(by[fr],key=lambda r:(int(r.get("YPos",1)),int(r.get("XPos",1)),int(r.get("_ordinal",0))))
            result.append([str(r.get("Phrase") or "") for r in rr if str(r.get("Phrase") or "")])
        return result

    def join_frames(ff):
        return "^".join("÷".join(x) for x in ff if x)

    import re
    _route_re=re.compile(r"^(?:[A-Z]?\d{1,4}[A-Z]?|\d{1,4}[A-Z]|[A-Z]\d{1,4}[A-Z]?)$", re.I)
    def _is_route_token(v): return bool(_route_re.match(str(v or "").replace(" ", "")))
    def _remove_route_run(els, token):
        if not token or not els: return list(els)
        target=_cc_flatnorm(token); vals=[_cc_flatnorm(x) for x in els]
        for i,v in enumerate(vals):
            if v==target and len(els)>1: return els[:i]+els[i+1:]
        for i in range(len(vals)):
            cur=""
            for j in range(i,min(len(vals),i+4)):
                cur += vals[j]
                if cur==target and len(els)>(j-i+1): return els[:i]+els[j+1:]
                if len(cur)>=len(target): break
        return list(els)

    out=[]
    for code in codes:
        ff=visual_frames(code,front); sf=visual_frames(code,side); rf=visual_frames(code,rear); of=visual_frames(code,odk)
        if color_front_only and ff:
            has_route=all(len(elements) >= 2 for elements in ff)
            route_parts=[elements[0] for elements in ff] if has_route else []
            destinations=[]; small_frames=[]
            for elements in ff:
                remaining=list(elements[1:] if has_route else elements)
                destinations.append(remaining[0] if remaining else "")
                small_frames.append("÷".join(remaining[1:]))
            while destinations and not destinations[-1]:
                destinations.pop()
            while small_frames and not small_frames[-1]:
                small_frames.pop()
            out.append({
                "MsgCode":code,"MsgClassID":3,"Approved":True,
                "Route":"^".join(route_parts) if has_route else "", "IDRoute":6,
                "Destination":"^".join(destinations), "IDDestination":7,
                "SmallSide":"^".join(small_frames), "IDSmallSide":14,
            })
            continue
        rear_summary=join_frames(rf)
        rear_first=(rf[0][0] if rf and rf[0] else "")
        repeated_front_route=bool(rear_first and ff and all(x and _cc_flatnorm(x[0])==_cc_flatnorm(rear_first) for x in ff))

        # 0101-era legacy projects use the rear rendering as the Route authoring
        # value, repeating a single route token once per destination frame.  The
        # older 0100 family leaves Route blank for PR/special text unless a
        # distinct route token is visibly paired with destination text.
        if odk_part=="0101":
            if repeated_front_route and len(rf)==1 and len(rf[0])==1:
                route_parts=[x[0] for x in ff]
                route="^".join(route_parts)
            else:
                route_parts=[]
                route=rear_summary
        else:
            has_distinct_pair=bool(repeated_front_route and any(len(x)>1 for x in ff))
            route_parts=[x[0] for x in ff] if has_distinct_pair else []
            route="^".join(route_parts)

        # Repair route tokens which the matrix compiler split into separate
        # glyph runs (N + 1, 1 + S), and recover numbered routes in 0100
        # projects where the rear sign alone was not enough to infer Route.
        odk_first=(of[0][0] if of and of[0] else "")
        if odk_part=="0101" and ("÷" in route) and _is_route_token(odk_first):
            route_parts=[odk_first]*max(1,len(ff)); route="^".join(route_parts)
        elif odk_part=="0100" and not route_parts and _is_route_token(odk_first):
            route_parts=[odk_first]*max(1,len(ff)); route="^".join(route_parts)

        # Destination is the primary-front wording. Remove the repeated route
        # even when the compiler placed it after destination text or split a
        # suffix into separate glyph runs.
        dest_frames=[]
        side_flat=[x for f in sf for x in f]
        for i,els0 in enumerate(ff):
            els=list(els0)
            if route_parts and els:
                tok=route_parts[i] if i<len(route_parts) else route_parts[-1]
                els=_remove_route_run(els,tok)
            if not route_parts:
                # Graphics may replace part of a word (e.g. V + "AMOS"). The
                # side display often carries the complete textual equivalent.
                repaired=[]
                for txt in els:
                    n=_cc_flatnorm(txt); candidates=[]
                    for st in side_flat:
                        sn=_cc_flatnorm(st)
                        if n and sn and (n==sn or sn.endswith(n) or n.endswith(sn)):
                            candidates.append(st)
                    exact=[x for x in candidates if _cc_flatnorm(x)==n]
                    repaired.append(max(exact or candidates,key=lambda x:len(_cc_flatnorm(x))) if candidates else txt)
                els=repaired
            dest_frames.append("÷".join(els))
        while dest_frames and not dest_frames[-1]:dest_frames.pop()
        destination="^".join(dest_frames)

        compact=bool(route_parts and len(sf)==len(ff) and sf and all(
            sf[i] and i<len(route_parts) and _cc_flatnorm(sf[i][0])==_cc_flatnorm(route_parts[i])
            for i in range(len(sf))))
        small_frames=[]
        for i,els0 in enumerate(sf):
            els=list(els0)
            tok=route_parts[i] if route_parts and i<len(route_parts) else (route_parts[-1] if route_parts else "")
            if odk_part=="0100" and tok:
                rest=_remove_route_run(els,tok)
                if len(rest)!=len(els):
                    small_frames.append((tok + (" " + " ".join(rest) if rest else "")).strip())
                    continue
            if compact and els and i<len(route_parts) and _cc_flatnorm(els[0])==_cc_flatnorm(route_parts[i]):
                els=els[1:]
            small_frames.append("÷".join(els))
        while small_frames and not small_frames[-1]:small_frames.pop()
        small="^".join(small_frames)

        out.append({"MsgCode":code,"MsgClassID":3,"Approved":True,
                    "Route":route,"IDRoute":6,
                    "Destination":destination,"IDDestination":7,
                    "SmallSide":small,"IDSmallSide":14})
    return out

def reconstruct_class_c_by_profile(frames: list[dict], sign_tables: dict | None = None, profile: str = "auto") -> list[dict]:
    p=(profile or "auto").lower()
    if p=="auto":p=infer_class_c_profile(sign_tables)
    if p=="legacy":return reconstruct_legacy_class_c_messages(frames,sign_tables)
    if p=="expanded":return reconstruct_class_c_messages(frames,sign_tables)
    raise ValueError(f"Unknown Class-C profile: {profile}")


def reconstruct_class_c_messages(frames: list[dict], sign_tables: dict | None = None) -> list[dict]:
    """Recover the expanded IPS Class-C authoring fields from compiled frames.

    Luminator's compiler removes the column labels but preserves the sign-specific
    renderings.  Cross-sign roles and frame ordering are sufficient to recover
    Route, DestinationTop, DestinationBot, DestinationSide and RouteSide for
    the supported IPS 3.x MTU grammar.
    """
    from collections import defaultdict
    from difflib import SequenceMatcher

    grouped = _cc_rows_by_code_sign(frames)
    roles = semantic_sign_roles(sign_tables)
    front=roles.get("front",2); side1=roles.get("side1",3); rear_lid=roles.get("rear",4); side2=roles.get("side2",5); titan=roles.get("titan",6); odk=roles.get("odk",1)
    codes = sorted({int(r["MsgCode"]) for r in frames if int(r.get("MsgClassID", 0)) == 3})
    out = []
    for code in codes:
        rear = _cc_idx_seq(grouped, code, rear_lid, 0)
        route = ""
        if rear:
            for lid in (front, side1, side2, titan):
                candidate = _cc_idx_seq(grouped, code, lid, 0)
                if candidate and _cc_flatnorm(candidate) == _cc_flatnorm(rear):
                    route = rear
                    break

        if route:
            top = _cc_idx_seq(grouped, code, front, 1)
        else:
            top = ""
            for lid in (front, titan, side1, side2, odk):
                candidate = _cc_idx_seq(grouped, code, lid, 0)
                if candidate:
                    top = candidate
                    break

        bot = side = route_side = ""
        if route:
            # The TITAN/front-family third visual element is the compiled
            # bottom-destination role, including multi-frame values.
            bot = _cc_idx_seq(grouped, code, titan, 2)
            side_candidate = _cc_idx_seq(grouped, code, side1, 1)
            if side_candidate and side_candidate != top:
                sp = side_candidate.split("^")
                tp = top.split("^")
                similarity = SequenceMatcher(None, _cc_flatnorm(side_candidate), _cc_flatnorm(top)).ratio()
                f1 = _cc_flatnorm(sp[0] if sp else "")
                f2 = _cc_flatnorm(tp[0] if tp else "")
                prefix = min(len(f1), len(f2), 5)
                first_related = prefix >= 3 and f1[:prefix] == f2[:prefix]
                # Multi-frame routes can cause SIDE to display a shortened
                # DestinationTop fallback.  Do not mislabel that as an explicit
                # DestinationSide value.
                fallback = ("^" in route and "^" in top and len(sp) <= len(tp)
                            and similarity >= 0.70 and first_related)
                if not fallback:
                    side = side_candidate
            route_side = _cc_idx_seq(grouped, code, side1, 0) if side else ""
        else:
            shape = _cc_rear_shape(grouped, code, rear_lid)
            lens = tuple(len(x) for x in shape)
            if not shape:
                bot = ""
            elif all(len(x) == 1 for x in shape):
                bot = _cc_idx_seq(grouped, code, rear_lid, 0)
            elif lens == (2, 1):
                bot = _cc_idx_seq(grouped, code, rear_lid, 0)
                side = _cc_idx_seq(grouped, code, rear_lid, 1)
            else:
                # Special rear templates render the top wording in a compact
                # form; the authoring bottom field is the un-framed top string.
                bot = top.replace("^", " ")

        out.append({
            "MsgCode": code, "MsgClassID": 3, "Approved": True,
            "Route": route, "IDRoute": 6,
            "DestinationTop": top, "IDDestinationTop": 14,
            "DestinationBot": bot, "IDDestinationBot": 15,
            "DestinationSide": side, "IDDestinationSide": 16,
            "RouteSide": route_side, "IDRouteSide": 17,
        })
    return out


def class_c_element_id_map(frames: list[dict], sign_tables: dict | None = None) -> dict[int, int]:
    """Return best semantic ElementID per frame-row ordinal.

    ElementID is partly template metadata and is not always serialized. This
    mapper restores the semantic field binding wherever the compiled text
    identifies it unambiguously. Runtime display output is unaffected.
    """
    grouped = _cc_rows_by_code_sign(frames)
    cc = {int(r["MsgCode"]): r for r in reconstruct_class_c_messages(frames, sign_tables)}
    roles = semantic_sign_roles(sign_tables); side_ids={roles.get("side1",3), roles.get("side2",5)}; rear_lid=roles.get("rear",4)
    result = {}

    def comps(v):
        return [x for x in str(v or "").split("^") if x]

    for (code, lid), rows in grouped.items():
        fields = cc.get(code, {})
        route = fields.get("Route", "")
        top = fields.get("DestinationTop", "")
        bot = fields.get("DestinationBot", "")
        side = fields.get("DestinationSide", "")
        rside = fields.get("RouteSide", "")
        rear_shape = _cc_rear_shape(grouped, code, rear_lid)
        for row in rows:
            phrase = str(row.get("Phrase") or "")
            if not phrase:
                result[int(row["_ordinal"])] = 14
                continue
            n = _cc_flatnorm(phrase)
            candidates = set()
            for field, eid in ((route, 6), (top, 14), (bot, 15), (side, 16), (rside, 17)):
                for component in comps(field):
                    cn = _cc_flatnorm(component)
                    if n == cn or (n and cn and (n in cn or cn in n)):
                        candidates.add(eid)

            # Sign-role priors resolve duplicate text values (e.g. Route == RouteSide).
            if lid in side_ids:
                if side and any(_cc_flatnorm(x) == n for x in comps(side)):
                    eid = 16
                elif rside and any(_cc_flatnorm(x) == n for x in comps(rside)):
                    eid = 17
                elif 14 in candidates:
                    eid = 14
                elif 6 in candidates:
                    eid = 6
                else:
                    eid = min(candidates) if candidates else 14
            elif lid == rear_lid:
                if route:
                    eid = 6
                elif rear_shape and all(len(x) == 1 for x in rear_shape):
                    eid = 15
                else:
                    eid = 6
            else:
                # Front/ODK/TITAN: explicit route pieces first, then top/bottom.
                if 6 in candidates and 14 not in candidates and 15 not in candidates:
                    eid = 6
                elif 14 in candidates:
                    eid = 14
                elif 15 in candidates:
                    eid = 15
                elif 6 in candidates:
                    eid = 6
                else:
                    eid = min(candidates) if candidates else 14
            result[int(row["_ordinal"])] = eid
    return result


def legacy_class_c_element_id_map(frames: list[dict], sign_tables: dict | None = None) -> dict[int,int]:
    """Best semantic ElementID map for legacy Route/Destination/SmallSide."""
    fields={int(r["MsgCode"]):r for r in reconstruct_legacy_class_c_messages(frames,sign_tables)}
    roles=semantic_sign_roles(sign_tables); front=roles.get("front"); side=roles.get("side1"); rear=roles.get("rear"); odk=roles.get("odk")
    result={}
    for ordinal,row in enumerate(frames):
        if int(row.get("MsgClassID",0))!=3:continue
        phrase=str(row.get("Phrase") or ""); lid=int(row.get("LSignID",0)); f=fields.get(int(row["MsgCode"]),{})
        n=_cc_flatnorm(phrase)
        route_parts=[_cc_flatnorm(x) for x in str(f.get("Route") or "").split("^") if x]
        if not phrase:
            result[ordinal]=0
        elif lid==side:
            # Side-display authoring is SmallSide unless a compact legacy
            # template explicitly renders the route as a separate element.
            result[ordinal]=6 if n in route_parts and str(f.get("SmallSide") or "").find(phrase)<0 else 14
        elif lid==front:
            result[ordinal]=6 if n in route_parts else 7
        elif lid==rear:
            result[ordinal]=6
        else:
            result[ordinal]=6 if n in route_parts else 7
    return result


def database_ready_messageframes(frames: list[dict], resources: dict, sign_tables: dict | None = None, class_c_profile: str = "auto") -> list[dict]:
    out=[]
    fmp=resources["font_index_map"]; gmp=resources["graphic_index_map"]
    resolved_profile=infer_class_c_profile(sign_tables) if (class_c_profile or "auto").lower()=="auto" else (class_c_profile or "expanded").lower()
    cc_eids = (legacy_class_c_element_id_map(frames, sign_tables) if resolved_profile=="legacy"
               else class_c_element_id_map(frames, sign_tables))
    for i,r in enumerate(frames, start=1):
        phrase=r.get("Phrase", "")
        gid=gmp.get(r.get("GraphicIndex")) if r.get("GraphicIndex") is not None else None
        fid=fmp.get(r.get("FontIndex")) if r.get("FontIndex") is not None else None
        # Element IDs are authoring/listing metadata.  Class-C receives a
        # semantic reconstruction pass below; graphics use 0.
        if gid is not None: eid=0
        elif r["MsgClassID"]==1: eid=1
        elif r["MsgClassID"]==2: eid=3
        else: eid=cc_eids.get(i - 1, 14)
        out.append({
            "MsgClassID":r["MsgClassID"], "MsgFrameID":i, "MsgCode":r["MsgCode"],
            "LSignID":r["LSignID"], "Frame":r["Frame"], "Break":r.get("Break",0),
            "Phrase":phrase, "GraphicID":gid, "FontID":fid, "LineTime":r["LineTime"],
            "HJustify":r["HJustify"], "VJustify":r["VJustify"],
            "XPos":r["XPos"], "YPos":r["YPos"],
            "Alert":False, "Scroll":False, "Format":False, "Blink":False,
            "Up":False, "Down":False, "Scroll2":False,
            "AttrBit0":False, "AttrBit1":False, "AttrBit2":False, "AttrBit3":False,
            "AttrBit4":False, "AttrBit5":False, "AttrBit6":False, "AttrBit7":False,
            "AttrBit9":False, "Number":0, "ElementID":eid,
        })
    return out


def compare_ips_embedding(mtu_data: bytes, ips_path: Path, chunk_size: int = 2032) -> dict:
    ips = ips_path.read_bytes()
    chunks = [mtu_data[i:i + chunk_size] for i in range(0, len(mtu_data), chunk_size)]
    found = []
    missing = []
    for i, ch in enumerate(chunks):
        pos = ips.find(ch)
        item = {"chunk": i, "mtu_offset": i * chunk_size, "length": len(ch)}
        if pos >= 0:
            item["ips_offset"] = pos
            found.append(item)
        else:
            missing.append(item)
    return {
        "ips_file": str(ips_path),
        "chunk_size": chunk_size,
        "chunk_count": len(chunks),
        "found_count": len(found),
        "missing_count": len(missing),
        "all_chunks_found": not missing,
        "found": found,
        "missing": missing,
    }


def extract(mtu_path: Path, outdir: Path, load_base: int,
            compare_ips: Path | None) -> dict:
    raw = mtu_path.read_bytes()
    mtu = MTU(raw, load_base)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "sections").mkdir(exist_ok=True)
    (outdir / "fonts").mkdir(exist_ok=True)
    (outdir / "graphics").mkdir(exist_ok=True)
    (outdir / "messages").mkdir(exist_ok=True)

    manifest = {
        "source_file": str(mtu_path),
        "file_size": len(raw),
        "sha256": sha256(raw),
        "load_base": load_base,
        "load_base_hex": f"0x{load_base:X}",
        "master_address": mtu.master_address,
        "master_address_hex": f"0x{mtu.master_address:08X}",
        "master_file_offset": mtu.master_offset,
        "master_file_offset_hex": f"0x{mtu.master_offset:X}",
        "sections": [],
    }

    for sec in mtu.sections:
        d = mtu.section_data(sec.index)
        fname = f"{sec.index:02d}_{sec.name}.bin"
        (outdir / "sections" / fname).write_bytes(d)
        manifest["sections"].append({
            "index": sec.index,
            "name": sec.name,
            "address": sec.address,
            "address_hex": f"0x{sec.address:08X}",
            "file_offset": sec.offset,
            "file_offset_hex": f"0x{sec.offset:X}",
            "length": sec.length,
            "sha256": sha256(d),
            "raw_file": f"sections/{fname}",
        })

    # Physical config = 128 big-endian 16-bit slots.
    phys = mtu.section_data(0)
    manifest["physical_config"] = {
        "u16be": [be16(phys, i) for i in range(0, len(phys), 2)],
        "nonzero": [
            {"slot": i // 2, "value": be16(phys, i), "value_hex": f"0x{be16(phys, i):04X}"}
            for i in range(0, len(phys), 2) if be16(phys, i)
        ],
    }

    cnf_records, cnf_tail = parse_fixed_records(mtu.section_data(1), 16)
    manifest["configuration_records"] = {
        "record_size": 16,
        "count": len(cnf_records),
        "records": cnf_records,
        "terminator_hex": cnf_tail.hex(" "),
    }

    # Fonts.
    fsec = mtu.sections[2]
    fdata = mtu.section_data(2)
    fheaders, _ = parse_pointer_resources(fdata, fsec.offset, load_base, "font")
    for i, h in enumerate(fheaders):
        start = h["file_offset"]
        end = fheaders[i + 1]["file_offset"] if i + 1 < len(fheaders) else mtu.sections[3].offset
        blob = raw[start:end]
        name = f"font_{i:03d}.bin"
        (outdir / "fonts" / name).write_bytes(blob)
        h.update({"length": len(blob), "sha256": sha256(blob), "raw_file": f"fonts/{name}"})
    manifest["fonts"] = {
        "count": len(fheaders),
        "header_size": 8,
        "field_hypothesis": {
            "param0": "likely font height/size",
            "param1": "likely spacing/type flag",
            "param2": "first character code",
            "param3": "last character code",
        },
        "resources": fheaders,
    }

    # Graphics.
    gsec = mtu.sections[3]
    gdata = mtu.section_data(3)
    gheaders, _ = parse_pointer_resources(gdata, gsec.offset, load_base, "graphic")
    for i, h in enumerate(gheaders):
        start = h["file_offset"]
        end = gheaders[i + 1]["file_offset"] if i + 1 < len(gheaders) else mtu.sections[4].offset
        blob = raw[start:end]
        name = f"graphic_{i:03d}.bin"
        (outdir / "graphics" / name).write_bytes(blob)
        h.update({"length": len(blob), "sha256": sha256(blob), "raw_file": f"graphics/{name}"})
    manifest["graphics"] = {
        "count": len(gheaders),
        "header_size": 8,
        "field_hypothesis": {
            "param0": "graphic dimension/format parameter 0",
            "param1": "graphic dimension/format parameter 1",
            "param2": "flags/reserved",
            "param3": "flags/reserved",
        },
        "resources": gheaders,
    }

    listing_records, listing_tail = parse_fixed_records(mtu.section_data(4), 16)
    manifest["listing_config"] = {
        "record_size": 16,
        "count": len(listing_records),
        "records": listing_records,
        "terminator_hex": listing_tail.hex(" "),
    }

    sign_tables = reconstruct_sign_tables(mtu)
    address_to_lsign = {int(x["PSignAddr"]): int(x["LSignID"]) for x in sign_tables["LogicalSignBuild"]}

    message_summary_rows = []
    banks = {}
    for bidx in range(11):
        sec_index = 5 + bidx
        letter = chr(ord("A") + bidx)
        sec = mtu.sections[sec_index]
        bdata = mtu.section_data(sec_index)
        records = split_message_bank(bdata, sec.offset, address_to_lsign)
        # Persist exact FE-delimited pieces too.
        bank_dir = outdir / "messages" / letter
        bank_dir.mkdir(exist_ok=True)
        for r in records:
            start = r["file_offset"]
            seg = raw[start:start + r["length"]]
            name = f"record_{r['record_index']:04d}.bin"
            (bank_dir / name).write_bytes(seg)
            r["raw_file"] = f"messages/{letter}/{name}"
            texts = [x["text"] for x in r["ascii"]]
            message_summary_rows.append({
                "bank": letter,
                "record_index": r["record_index"],
                "message_slot": r.get("message_slot"),
                "segment_count": len(r.get("segments", [])),
                "file_offset_hex": r["file_offset_hex"],
                "length": r["length"],
                "texts": " | ".join(texts),
            })
        banks[letter] = {
            "section_length": len(bdata),
            "record_count": len(records),
            "terminator_hex": bdata[-4:].hex(" ") if bdata else "",
            "records": records,
        }
    manifest["message_banks"] = banks

    for table_name, rows in sign_tables.items():
        out_name = f"recovered_{table_name.lower()}.csv"
        if rows:
            fields = list(rows[0].keys())
            with (outdir / out_name).open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader(); w.writerows(rows)
    manifest["recovered_sign_tables"] = {k: len(v) for k, v in sign_tables.items()}

    # Normalized reconstruction model: this is intentionally database-neutral.
    project_messages = []
    for letter, bank in banks.items():
        for rec in bank["records"]:
            project_messages.append({
                "bank": letter,
                "message_slot": rec.get("message_slot"),
                "source_offset": rec["file_offset"],
                "segments": rec.get("segments", []),
            })
    project_model = {
        "format": "Luminator IPS 3.x MTU reconstructed intermediate model",
        "source_file": str(mtu_path),
        "message_count": len(project_messages),
        "messages": project_messages,
        "font_count": len(fheaders),
        "graphic_count": len(gheaders),
        "configuration_record_count": len(cnf_records),
        "listing_record_count": len(listing_records),
    }
    manifest["project_model_file"] = "project_model.json"
    with (outdir / "project_model.json").open("w", encoding="utf-8") as f:
        json.dump(project_model, f, indent=2, ensure_ascii=False)

    font_metrics = build_font_metrics(raw, fheaders, mtu.sections[3].offset)
    recovered_frames = reconstruct_messageframes(banks, font_metrics, sign_tables)
    project_model["recovered_messageframe_count"] = len(recovered_frames)
    resources = reconstruct_resource_tables(raw, mtu, fheaders, gheaders, recovered_frames, sign_tables)
    effect_zones = reconstruct_effect_zones(recovered_frames, sign_tables)
    db_frames = database_ready_messageframes(recovered_frames, resources)
    # Database-ready resource/sign/frame tables.
    extra_tables = {
        "Fonts": resources["Fonts"], "Graphics": resources["Graphics"],
        "EffectZones": effect_zones, "MessageFramesDB": db_frames,
    }
    for table_name, rows in extra_tables.items():
        if not rows: continue
        out_name=f"recovered_{table_name.lower()}.csv"
        fields=list(rows[0].keys())
        with (outdir/out_name).open("w", newline="", encoding="utf-8") as f:
            w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
    manifest["recovered_resource_tables"]={
        "Fonts":len(resources["Fonts"]), "Graphics":len(resources["Graphics"]),
        "EffectZones":len(effect_zones), "MessageFramesDB":len(db_frames),
        "graphic_group_size":resources["graphic_group_size"],
    }
    recovered_fields = [
        "MsgClassID", "MsgCode", "LSignID", "Frame", "Break", "Phrase",
        "GraphicIndex", "FontIndex", "LineTime", "HJustify", "VJustify",
        "XPos", "YPos", "Alert", "Scroll", "Format", "Blink", "Up",
        "Down", "Scroll2", "source_segment", "selector_hex",
    ]
    with (outdir / "recovered_messageframes.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=recovered_fields)
        w.writeheader(); w.writerows(recovered_frames)
    with (outdir / "recovered_messageframes.json").open("w", encoding="utf-8") as f:
        json.dump(recovered_frames, f, indent=2, ensure_ascii=False)
    manifest["recovered_messageframes"] = {
        "count": len(recovered_frames),
        "csv": "recovered_messageframes.csv",
        "json": "recovered_messageframes.json",
    }

    if compare_ips:
        manifest["ips_embedding_comparison"] = compare_ips_embedding(raw, compare_ips)

    with (outdir / "messages.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["bank", "record_index", "message_slot", "segment_count", "file_offset_hex", "length", "texts"])
        w.writeheader()
        w.writerows(message_summary_rows)

    with (outdir / "manifest.json").open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract/reverse Luminator IPS 3.x MTU structure")
    ap.add_argument("mtu", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=Path("mtu_recovered"))
    ap.add_argument("--load-base", type=lambda x: int(x, 0), default=DEFAULT_LOAD_BASE)
    ap.add_argument("--compare-ips", type=Path)
    args = ap.parse_args()

    m = extract(args.mtu, args.out, args.load_base, args.compare_ips)
    print(f"MTU SHA-256: {m['sha256']}")
    print(f"Master table: {m['master_address_hex']} -> file {m['master_file_offset_hex']}")
    print("Sections:")
    for s in m["sections"]:
        print(f"  {s['index']:2d} {s['name']:<22} {s['file_offset_hex']:>8}  {s['length']:7d} bytes")
    print(f"Fonts: {m['fonts']['count']}")
    print(f"Graphics: {m['graphics']['count']}")
    print(f"Configuration records: {m['configuration_records']['count']}")
    print(f"Listing/sign records: {m['listing_config']['count']}")
    print("Message records: " + ", ".join(f"{k}={v['record_count']}" for k, v in m['message_banks'].items()))
    if "ips_embedding_comparison" in m:
        c = m["ips_embedding_comparison"]
        print(f"MTU chunks found in IPS: {c['found_count']}/{c['chunk_count']}")
    print(f"Wrote: {args.out / 'manifest.json'}")
    print(f"Wrote: {args.out / 'messages.csv'}")
    print(f"Wrote: {args.out / 'project_model.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
