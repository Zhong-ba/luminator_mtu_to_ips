from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import mtu_reverse as mr
import build_ips_windows as builder


def test_selector_mask_addresses_known_examples():
    assert mr.selector_mask_addresses(0x0002) == [1]
    assert mr.selector_mask_addresses(0x0101) == [8]
    assert mr.selector_mask_addresses(0x0120) == [13]
    assert mr.selector_mask_addresses(0x0140) == [14]
    assert mr.selector_mask_addresses(0x0160) == [13, 14]


def test_decode_selector_resolves_addresses():
    selector, used = mr.decode_selector(bytes.fromhex("01 60"), 0, {13: 7, 14: 8})
    assert used == 2
    assert selector["physical_addresses"] == [13, 14]
    assert selector["targets"] == [7, 8]
    assert selector["unconfigured_addresses"] == []
    assert selector["unknown_masks"] == []


def test_decode_selector_marks_unconfigured_addresses_without_invalidating_mask():
    selector, used = mr.decode_selector(bytes.fromhex("00 10"), 0, {1: 1, 2: 2})

    assert used == 2
    assert selector["physical_addresses"] == [4]
    assert selector["targets"] == []
    assert selector["unconfigured_addresses"] == [4]
    assert selector["unknown_masks"] == []


def test_decode_selector_recognizes_legacy_empty_placeholder():
    selector, used = mr.decode_selector(bytes.fromhex("ED 03 00"), 0, {1: 1})

    assert used == 3
    assert selector["kind"] == "legacy_empty_selector"
    assert selector["targets"] == []
    assert selector["empty_placeholder"] is True


@pytest.mark.parametrize(("mask_hex", "addresses", "targets"), [
    ("00 02 01 10 02 02", [1, 12, 17], [1, 2, 7]),
    ("00 02 01 D0 02 02", [1, 12, 14, 15, 17], [1, 2, 4, 5, 7]),
])
@pytest.mark.parametrize("offset", [0, 2])
def test_decode_selector_distinguishes_three_masks_from_empty_placeholder(
        mask_hex, addresses, targets, offset):
    data = b"\x00" * offset + bytes.fromhex(f"ED 03 {mask_hex} F7 00 0A") + b"TEST"
    address_map = {1: 1, 12: 2, 14: 4, 15: 5, 17: 7}

    selector, used = mr.decode_selector(data, offset, address_map)

    assert used == offset + 8
    assert selector["kind"] == "selector_list"
    assert selector["raw_hex"] == f"ed 03 {mask_hex.lower()}"
    assert selector["physical_addresses"] == addresses
    assert selector["targets"] == targets
    assert selector["unknown_masks"] == []
    assert not selector.get("empty_placeholder")


@pytest.mark.parametrize("selector_hex", [
    "ED 03", "ED 03 00 02", "ED 03 00 02 01", "ED 03 00 02 01 10",
    "ED 03 00 02 01 10 02",
])
def test_decode_selector_rejects_truncated_three_mask_list(selector_hex):
    with pytest.raises(ValueError, match="truncated ED selector list"):
        mr.decode_selector(bytes.fromhex(selector_hex), 0, {1: 1})


@pytest.mark.parametrize("placeholder_position", ["first", "middle", "last"])
def test_parse_message_segments_preserves_empty_placeholder(placeholder_position):
    populated = bytes.fromhex("00 02 F7 00 0A") + b"TEST"
    placeholder = bytes.fromhex("ED 03 00")
    parts = {
        "first": [placeholder, populated],
        "middle": [populated, placeholder, populated],
        "last": [populated, placeholder],
    }[placeholder_position]

    segments = mr.parse_message_segments(b"\xFC".join(parts), {1: 1})

    assert len(segments) == len(parts)
    for segment, part in zip(segments, parts):
        if part == placeholder:
            assert segment["selector"]["empty_placeholder"] is True
            assert segment["target_lsign_ids"] == []
            assert segment["body_length"] == 0
        else:
            assert segment["target_lsign_ids"] == [1]
            assert segment["text"] == "TEST"


def test_parse_message_segments_keeps_three_mask_bytes_out_of_body():
    payload = bytes.fromhex("ED 03 00 02 01 10 02 02 F7 00 0A") + b"TEST"

    segments = mr.parse_message_segments(payload, {1: 1, 12: 2, 17: 7})

    assert len(segments) == 1
    assert segments[0]["target_lsign_ids"] == [1, 2, 7]
    assert segments[0]["body_offset"] == 8
    assert segments[0]["text"] == "TEST"
    assert all(token["kind"] != "byte" for token in segments[0]["controls"])


def test_decode_selector_recognizes_legacy_full_project_selector():
    selector, used = mr.decode_selector(bytes.fromhex("01 FF 02 7F"), 0, {8: 8, 22: 22})

    assert used == 4
    assert selector["kind"] == "legacy_selector_list"
    assert selector["physical_addresses"] == list(range(8, 23))
    assert selector["targets"] == [8, 22]


def test_decode_selector_recognizes_legacy_sparse_selector_list():
    selector, used = mr.decode_selector(bytes.fromhex("01 7F 02 04"), 0, {8: 8, 14: 14, 18: 18})

    assert used == 4
    assert selector["kind"] == "legacy_selector_list"
    assert selector["physical_addresses"] == [*range(8, 15), 18]
    assert selector["targets"] == [8, 14, 18]


def test_decode_segment_body_recognizes_crlf_line_ending():
    decoded = mr.decode_segment_body(b"TO WATERFRONT STN \r\n")

    assert decoded["text"] == "TO WATERFRONT STN "
    assert decoded["controls"][-1]["semantic"] == "line_ending"
    assert decoded["controls"][-1]["opcode"] == "0x0D0A"


def test_decode_segment_body_recognizes_windows_1252_apostrophe_as_text():
    decoded = mr.decode_segment_body(b"Place d\x92Orleans")

    assert decoded["text"] == "Place d’Orleans"
    assert decoded["controls"] == [{
        "kind": "text", "offset": 0, "text": "Place d’Orleans",
        "bytes_hex": "50 6c 61 63 65 20 64 92 4f 72 6c 65 61 6e 73",
    }]


def test_decode_segment_body_preserves_quote_and_backslash_as_text():
    decoded = mr.decode_segment_body(b'QUOTE " AND BACKSLASH \\')

    assert decoded["text"] == 'QUOTE " AND BACKSLASH \\'
    assert decoded["controls"] == [{
        "kind": "text", "offset": 0, "text": 'QUOTE " AND BACKSLASH \\',
        "bytes_hex": "51 55 4f 54 45 20 22 20 41 4e 44 20 42 41 43 4b 53 4c 41 53 48 20 5c",
    }]


def test_identify_unknown_message_tokens_includes_context_and_frequency():
    decoded = mr.decode_segment_body(b"ABC\x01DEF")
    model = {
        "banks": {
            "C": {
                "records": [{
                    "msg_code": 42,
                    "file_offset": 0x100,
                    "segments": [{
                        "segment_index": 3,
                        "body_offset": 2,
                        "body_hex": "41 42 43 01 44 45 46",
                        "selector": {"raw_hex": "01 08"},
                        "target_lsign_ids": [5],
                        "controls": decoded["controls"],
                    }],
                }],
            },
        },
    }

    assert builder.identify_unknown_message_tokens(model) == [{
        "kind": "raw_byte",
        "token": "0x01",
        "occurrences": 1,
        "examples": [{
            "bank": "C",
            "message_code": 42,
            "record_file_offset": "0x100",
            "segment_index": 3,
            "body_offset": 2,
            "token_offset": 3,
            "selector_hex": "01 08",
            "target_lsign_ids": [5],
            "context_hex": "41 42 43 01 44 45 46",
        }],
    }]


def test_decode_segment_body_preserves_opaque_fa_control():
    decoded = mr.decode_segment_body(bytes.fromhex("FA 20 00 F7 00 25"))

    assert decoded["controls"][0]["semantic"] == "opaque_control_fa"
    assert decoded["controls"][0]["params"] == [0x20, 0x00]
    assert decoded["controls"][1]["font_index"] == 37


def test_decode_segment_body_recognizes_rgb_color_planes():
    decoded = mr.decode_segment_body(bytes.fromhex("FA 00 80 FA 00 40 FA 00 20"))

    assert [control["semantic"] for control in decoded["controls"]] == ["color_plane"] * 3
    assert [control["color_mask"] for control in decoded["controls"]] == [1, 2, 4]
    assert [control["color_intensity"] for control in decoded["controls"]] == [255, 255, 255]


def test_decode_segment_body_recognizes_dim_rgb_color_planes():
    decoded = mr.decode_segment_body(bytes.fromhex("FA 00 90 FA 00 50 FA 00 30"))

    assert [control["color_mask"] for control in decoded["controls"]] == [1, 2, 4]
    assert [control["color_intensity"] for control in decoded["controls"]] == [128, 128, 128]


def test_color_plane_frames_become_editable_color_zone():
    frames = [
        {"MsgClassID": 3, "MsgCode": 999, "LSignID": 1, "Frame": 1,
         "Phrase": "SPECTRUM", "GraphicIndex": None, "FontIndex": 2,
         "XPos": 30, "YPos": 5, "ColorMask": 1},
        {"MsgClassID": 3, "MsgCode": 999, "LSignID": 1, "Frame": 2,
         "Phrase": "", "GraphicIndex": None, "FontIndex": None,
         "XPos": 1, "YPos": 1, "ColorMask": 2},
        {"MsgClassID": 3, "MsgCode": 999, "LSignID": 1, "Frame": 3,
         "Phrase": "", "GraphicIndex": None, "FontIndex": None,
         "XPos": 1, "YPos": 1, "ColorMask": 4},
    ]
    sign_tables = {"LogicalSigns": [{"LSignID": 1, "LSignDotWidth": 112, "LSignDotHeight": 16}]}

    zones = mr.reconstruct_color_zones(frames, sign_tables)
    collapsed = mr.collapse_color_plane_frames(frames)

    assert zones == [{
        "MsgClassID": 3, "MsgCode": 999, "LSignID": 1, "Frame": 1,
        "Phrase": "SPECTRUM", "ColorStr": "\\C01SPECTRUM\\E", "GraphicID": 0,
        "Text": "SPECTRUM", "ColorNumber": 255,
        "XStart": 0, "YStart": 0, "XEnd": 111, "YEnd": 16,
    }]
    assert len(collapsed) == 1
    assert collapsed[0]["Frame"] == 1


def test_color_plane_frames_combine_into_yellow():
    frames = [
        {"MsgClassID": 3, "MsgCode": 58, "LSignID": 1, "Frame": 1,
         "Phrase": "58", "XPos": 1, "YPos": 1, "ColorMask": 1},
        {"MsgClassID": 3, "MsgCode": 58, "LSignID": 1, "Frame": 2,
         "Phrase": "58", "XPos": 1, "YPos": 1, "ColorMask": 2},
    ]
    sign_tables = {"LogicalSigns": [{"LSignID": 1, "LSignDotWidth": 112, "LSignDotHeight": 16}]}

    zone = mr.reconstruct_color_zones(frames, sign_tables)[0]

    assert zone["ColorStr"] == "\\C0458\\E"
    assert zone["ColorNumber"] == 65535


def test_color_plane_frames_combine_bright_and_dim_channels():
    frames = [
        {"MsgClassID": 3, "MsgCode": 193, "LSignID": 1, "Frame": 1,
         "source_segment": 0, "Phrase": "CANADA LINE", "XPos": 1, "YPos": 1,
         "ColorMask": 1, "ColorIntensity": 128},
        {"MsgClassID": 3, "MsgCode": 193, "LSignID": 1, "Frame": 2,
         "source_segment": 1, "Phrase": "CANADA LINE", "XPos": 1, "YPos": 1,
         "ColorMask": 2, "ColorIntensity": 255},
        {"MsgClassID": 3, "MsgCode": 193, "LSignID": 1, "Frame": 3,
         "source_segment": 2, "Phrase": "CANADA LINE", "XPos": 1, "YPos": 1,
         "ColorMask": 4, "ColorIntensity": 255},
    ]
    sign_tables = {"LogicalSigns": [{"LSignID": 1, "LSignDotWidth": 112, "LSignDotHeight": 16}]}

    zone = mr.reconstruct_color_zones(mr.assign_color_frame_numbers(frames), sign_tables)[0]

    assert zone["ColorStr"] == "\\C12CANADA LINE\\E"
    assert zone["ColorNumber"] == 16777088


def test_compiler_rgb_placeholder_restores_literal_caret_text():
    frames = [
        {"MsgClassID": 3, "MsgCode": 8, "LSignID": 2, "Frame": 1,
         "ColorFrame": 1, "ColorMask": 1, "ColorIntensity": 255,
         "Phrase": "R", "FontIndex": 1, "XPos": 29, "YPos": 1},
        {"MsgClassID": 3, "MsgCode": 8, "LSignID": 2, "Frame": 2,
         "ColorFrame": 1, "ColorMask": 2, "ColorIntensity": 255,
         "Phrase": "G", "FontIndex": 1, "XPos": 29, "YPos": 1},
        {"MsgClassID": 3, "MsgCode": 8, "LSignID": 2, "Frame": 3,
         "ColorFrame": 1, "ColorMask": 4, "ColorIntensity": 255,
         "Phrase": "B", "FontIndex": 1, "XPos": 29, "YPos": 1},
        {"MsgClassID": 3, "MsgCode": 8, "LSignID": 2, "Frame": 4,
         "ColorFrame": 2, "ColorMask": 1, "ColorIntensity": 255,
         "Phrase": "_`", "FontIndex": 1, "XPos": 29, "YPos": 1},
        {"MsgClassID": 3, "MsgCode": 8, "LSignID": 2, "Frame": 5,
         "ColorFrame": 2, "ColorMask": 2, "ColorIntensity": 255,
         "Phrase": "", "FontIndex": None, "XPos": 1, "YPos": 1},
        {"MsgClassID": 3, "MsgCode": 8, "LSignID": 2, "Frame": 6,
         "ColorFrame": 2, "ColorMask": 4, "ColorIntensity": 255,
         "Phrase": "", "FontIndex": None, "XPos": 1, "YPos": 1},
    ]

    assert mr.collapse_compiler_rgb_placeholders(frames) == [{
        "MsgClassID": 3, "MsgCode": 8, "LSignID": 2, "Frame": 1,
        "ColorFrame": 2, "ColorMask": None, "ColorIntensity": None,
        "Phrase": "^_`", "FontIndex": 1, "XPos": 29, "YPos": 1,
    }]


def test_color_palette_includes_all_bright_and_dim_choices():
    assert len(mr.COLOR_TOKENS) == 26
    assert set(mr.COLOR_TOKENS.values()) == set(range(1, 27))
    assert mr.COLOR_TOKENS[(0, 128, 255)] == 14
    assert mr.COLOR_TOKENS[(128, 128, 255)] == 16
    assert mr.COLOR_TOKENS[(128, 128, 128)] == 26


def test_legacy_class_c_recovers_color_front_listing_fields():
    sign_tables = {
        "PhysicalSigns": [{"PSignID": 1, "PSignPartNumber": "08E0", "PSignType": "Matrix",
                            "LogicalDotWidth": 112, "LogicalDotHeight": 16}],
        "LogicalSigns": [{"LSignID": 1, "LSignDotWidth": 112, "LSignDotHeight": 16}],
        "LogicalSignBuild": [{"PSignID": 1, "LSignID": 1}],
    }
    frames = [
        {"MsgClassID": 3, "MsgCode": 58, "LSignID": 1, "Frame": 1, "Phrase": "58", "XPos": 1, "YPos": 1},
        {"MsgClassID": 3, "MsgCode": 58, "LSignID": 1, "Frame": 1, "Phrase": "S.F.U.:EDMONDS", "XPos": 32, "YPos": 5},
        {"MsgClassID": 3, "MsgCode": 998, "LSignID": 1, "Frame": 1, "Phrase": "MUNICIPAL RAILWAY", "XPos": 2, "YPos": 1},
        {"MsgClassID": 3, "MsgCode": 998, "LSignID": 1, "Frame": 1, "Phrase": "SAN FRANCISCO", "XPos": 18, "YPos": 10},
    ]

    listings = {row["MsgCode"]: row for row in mr.reconstruct_legacy_class_c_messages(frames, sign_tables)}

    assert (listings[58]["Route"], listings[58]["Destination"], listings[58]["SmallSide"]) == ("58", "S.F.U.:EDMONDS", "")
    assert (listings[998]["Route"], listings[998]["Destination"], listings[998]["SmallSide"]) == ("MUNICIPAL RAILWAY", "SAN FRANCISCO", "")


def test_font_body_hash_ignores_ips_authoring_header():
    compiled = bytes.fromhex("00 06 00 08 00 0B AA BB CC DD EE")
    blob_a = b"A" * 28 + compiled
    blob_b = b"B" * 28 + compiled

    assert builder._font_body_hash(blob_a) == builder._font_body_hash(blob_b)
    assert builder._font_body_hash(b"short") is None


@pytest.mark.parametrize(("indexes", "chosen"), [
    ([0], 0),
    ([1], 1),
    ([], 0),
    ([0, 1, 1], 1),
    ([1, 0], 0),
])
def test_reconstruct_resource_tables_selects_referenced_graphic_variant(indexes, chosen):
    bodies = [
        bytes.fromhex("00 04 00 08 01 00 01 00"),
        bytes.fromhex("00 04 00 0C FF FF FF FF FF FF FF FF"),
        bytes.fromhex("00 04 00 0C FF FF FF FF FF FF FF FF"),
        bytes.fromhex("00 04 00 0C 00 00 00 00 00 00 00 00"),
        bytes.fromhex("00 04 00 08 00 00 00 00"),
    ]
    raw = bytearray()
    headers = []
    for index, body in enumerate(bodies):
        headers.append({
            "index": index, "file_offset": len(raw),
            "param0": 16 if index in (0, 4) else 14,
            "param1": 1 if index in (0, 4) else 0, "param2": 0, "param3": 0,
        })
        raw.extend(body)
    mtu = SimpleNamespace(sections=[None] * 4 + [SimpleNamespace(offset=len(raw))])
    frames = [{"GraphicIndex": index} for index in indexes] + [{"GraphicIndex": None}, {}]

    resources = mr.reconstruct_resource_tables(bytes(raw), mtu, [], headers, frames, {})
    graphic = resources["Graphics"][0]

    assert bytes.fromhex(graphic["GraphicBlobHex"])[28:] == bodies[chosen]
    assert graphic["GraphicHeight"] == headers[chosen]["param0"]
    assert graphic["GraphicWidth"] == mr.be16(bodies[chosen], 2)
    assert graphic["RedGraphicBlobHex"] is None
    assert graphic["GreenGraphicBlobHex"] is None
    assert graphic["BlueGraphicBlobHex"] is None
    assert resources["graphic_index_map"] == dict.fromkeys(range(5), 1)


@pytest.mark.parametrize("resource_count", [0, 1, 5, 60, 501])
def test_recovered_graphic_names_are_unique_and_eight_characters(resource_count):
    body = bytes.fromhex("00 04 00 06 AA BB")
    raw = body * resource_count
    headers = [{
        "index": index, "file_offset": index * len(body),
        "param0": 16, "param1": 1, "param2": 0, "param3": 0,
    } for index in range(resource_count)]
    mtu = SimpleNamespace(sections=[None] * 4 + [SimpleNamespace(offset=len(raw))])

    resources = mr.reconstruct_resource_tables(raw, mtu, [], headers, [], {})
    graphics = resources["Graphics"]
    names = [graphic["GraphicName"] for graphic in graphics]
    group_size = 5 if resource_count and resource_count % 5 == 0 else 1

    assert len(graphics) == resource_count // group_size
    assert names == [f"RG{index:06d}" for index in range(len(graphics))]
    assert all(len(name) == 8 and name.isascii() for name in names)
    assert len({name.casefold() for name in names}) == len(names)
    assert resources["graphic_index_map"] == {
        index: index // group_size + 1 for index in range(resource_count)
    }


@pytest.mark.parametrize("resource_count", [0, 1, 12, 101])
def test_recovered_font_filenames_use_unique_eight_character_stems(resource_count):
    body = bytes.fromhex("00 04 00 06 AA BB")
    raw = body * resource_count
    headers = [{
        "index": index, "file_offset": index * len(body),
        "param0": 8, "param1": 1, "param2": 65, "param3": 65,
    } for index in range(resource_count)]
    mtu = SimpleNamespace(sections=[None] * 3 + [
        SimpleNamespace(offset=len(raw)), SimpleNamespace(offset=len(raw)),
    ])

    resources = mr.reconstruct_resource_tables(raw, mtu, headers, [], [], {})
    fonts = resources["Fonts"]
    filenames = [font["FontFile"] for font in fonts]

    assert filenames == [f"RF{index:06d}.fnt" for index in range(resource_count)]
    assert all(len(Path(name).stem) == 8 and Path(name).suffix == ".fnt" for name in filenames)
    assert len({name.casefold() for name in filenames}) == resource_count
    assert [font["FontName"] for font in fonts] == [
        f"Recovered{index:02d}" for index in range(resource_count)
    ]
    assert all(bytes.fromhex(font["FontBlobHex"])[28:] == body for font in fonts)
    assert resources["font_index_map"] == {
        index: index + 1 for index in range(resource_count)
    }


@pytest.mark.parametrize(("default_font_names", "expected"), [
    (None, "RF000011"),
    ({}, "RF000011"),
    ({11: "L5vw"}, "L5vw"),
    ({0: "Standard"}, "RF000011"),
])
def test_physical_default_font_uses_file_stem(default_font_names, expected):
    physical = {
        "PSignID": 1, "PSignName": "TEST", "PSignPartNumber": "TEST",
        "PSignType": "Matrix", "DefaultFontIndex": 11,
        "PSignDotHeight": 16, "PSignDotWidth": 160,
        "PSignCharWidth": 0, "PSignCharLines": 0, "PSignNumChars": 0,
        "PSignCharHeight": 0, "PSignLineTime": 16, "PSignBlankTime": 0,
        "PSignBlankBeforePR": False, "PSignBlankBeforeRPT": False,
        "Emergency": False, "PSignAddr": 1,
    }

    row = builder.enrich_physical_row(physical, default_font_names)

    assert row["DefaultFont"] == expected


def test_reconstruct_resource_tables_preserves_color_graphic_planes():
    bodies = [
        bytes.fromhex("00 04 00 34 0F FF 0F FF"),
        bytes.fromhex("00 04 00 34 0C 3F 0C 3F"),
        bytes.fromhex("00 04 00 34 00 FC 00 FC"),
        bytes.fromhex("00 04 00 34 0F 00 0F 00"),
        bytes.fromhex("00 04 00 34 00 00 00 00"),
    ]
    offsets = [100 + len(bodies[0]) * index for index in range(len(bodies))]
    raw = bytearray(200)
    for offset, body in zip(offsets, bodies):
        raw[offset:offset + len(body)] = body
    headers = [{
        "index": index, "file_offset": offset, "param0": 16,
        "param1": 1 if index in (0, 4) else 0, "param2": 0, "param3": 0,
    } for index, offset in enumerate(offsets)]
    mtu = SimpleNamespace(sections=[None, None, None, None, SimpleNamespace(offset=140)])

    resource = mr.reconstruct_resource_tables(bytes(raw), mtu, [], headers, [], {})["Graphics"][0]

    assert bytes.fromhex(resource["GraphicBlobHex"])[28:] == bodies[0]
    assert bytes.fromhex(resource["RedGraphicBlobHex"])[28:] == bodies[1]
    assert bytes.fromhex(resource["GreenGraphicBlobHex"])[28:] == bodies[2]
    assert bytes.fromhex(resource["BlueGraphicBlobHex"])[28:] == bodies[3]


def _sign_tables_with_rear(address):
    return {
        "PhysicalSigns": [
            {"PSignID": 1, "PSignAddr": address, "PSignPartNumber": "08B5", "LogicalDotWidth": 48, "LogicalDotHeight": 16}
        ],
        "LogicalSignBuild": [{"PSignID": 1, "LSignID": 1}],
    }


def test_class_c_profile_detection():
    assert mr.infer_class_c_profile(_sign_tables_with_rear(10)) == "expanded"
    assert mr.infer_class_c_profile(_sign_tables_with_rear(12)) == "legacy"


def test_legacy_listing_uses_geometry_when_part_numbers_are_unknown():
    sign_tables = {
        "PhysicalSigns": [
            {"PSignID": 1, "PSignPartNumber": "0410", "PSignType": "Matrix", "LogicalDotWidth": 160, "LogicalDotHeight": 16},
            {"PSignID": 2, "PSignPartNumber": "0411", "PSignType": "Matrix", "LogicalDotWidth": 96, "LogicalDotHeight": 8},
            {"PSignID": 3, "PSignPartNumber": "0412", "PSignType": "Matrix", "LogicalDotWidth": 48, "LogicalDotHeight": 16},
        ],
        "LogicalSignBuild": [
            {"PSignID": 1, "LSignID": 1}, {"PSignID": 2, "LSignID": 2}, {"PSignID": 3, "LSignID": 3},
        ],
    }
    frames = [
        {"MsgClassID": 3, "MsgCode": 42, "LSignID": 1, "Frame": 1, "Phrase": "42", "XPos": 1, "YPos": 1},
        {"MsgClassID": 3, "MsgCode": 42, "LSignID": 1, "Frame": 1, "Phrase": "DOWNTOWN", "XPos": 30, "YPos": 1},
        {"MsgClassID": 3, "MsgCode": 42, "LSignID": 2, "Frame": 1, "Phrase": "42", "XPos": 1, "YPos": 1},
        {"MsgClassID": 3, "MsgCode": 42, "LSignID": 2, "Frame": 1, "Phrase": "VIA MAIN", "XPos": 20, "YPos": 1},
        {"MsgClassID": 3, "MsgCode": 42, "LSignID": 3, "Frame": 1, "Phrase": "42", "XPos": 1, "YPos": 1},
    ]

    listing = mr.reconstruct_legacy_class_c_messages(frames, sign_tables)[0]

    assert (listing["Route"], listing["Destination"], listing["SmallSide"]) == ("42", "DOWNTOWN", "VIA MAIN")


def test_reconstruct_sign_tables_reads_legacy_companion_matrix_geometry():
    physical = bytearray(256)
    physical[2:4] = bytes.fromhex("10 01")
    physical[4:6] = bytes.fromhex("04 28")
    config = bytes.fromhex(
        "10 01 00 55 55 55 55 55 55 55 55 55 55 55 55 55"
        "10 01 40 10 00 00 00 00 00 00 00 80 00 10 00 1c"
        "04 28 00 0e 10 1c 1e 1e 0f 10 00 00 00 00 00 00"
        "04 28 40 00 07 00 00 00 00 00 00 67 00 10 0e 21")
    listing = bytes.fromhex(
        "01 00 00 00 10 03 01 01 00 00 00 00 8f 00 00 00"
        "02 00 00 09 10 03 00 00 00 02 00 00 00 00 00 00")
    section_data = [bytes(physical), config, b"", b"", listing] + [b""] * 11
    offsets = []
    data = bytearray(68)
    for content in section_data:
        offsets.append(len(data))
        data.extend(content)
    for index, offset in enumerate(offsets):
        data[4 + index * 4:8 + index * 4] = (mr.DEFAULT_LOAD_BASE + offset).to_bytes(4, "big")
    data[:4] = (mr.DEFAULT_LOAD_BASE + 4).to_bytes(4, "big")

    signs = mr.reconstruct_sign_tables(mr.MTU(bytes(data)))["LogicalSigns"]

    assert [(row["LSignDotHeight"], row["LSignDotWidth"]) for row in signs] == [(16, 128), (16, 103)]


def test_preflight_minimal_failure_is_structured():
    model = {
        "banks": {},
        "sign_tables": {"LogicalSigns": []},
        "resources": {"Fonts": [], "Graphics": []},
        "db_frames": [],
        "effect_zones": [],
        "raw_mtu": b"abc",
        "class_c_profile": "legacy",
    }
    report = builder.preflight_model(model)
    assert report["status"] == "PASS"
    assert report["mtu_sha256"]


def test_preflight_warns_when_declared_message_banks_have_no_records():
    model = {
        "banks": {"A": {"records": []}},
        "sign_tables": {"LogicalSigns": []},
        "resources": {"Fonts": [], "Graphics": []},
        "db_frames": [],
        "effect_zones": [],
        "raw_mtu": b"empty-message-bank",
        "class_c_profile": "legacy",
    }

    report = builder.preflight_model(model)

    assert report["status"] == "PASS"
    assert report["message_records"] == 0
    assert report["message_classes"] == {}
    assert report["warnings"] == [
        "MTU contains no compiled message records; no Class A-K messages can be recovered"
    ]


def test_preflight_reports_only_populated_message_classes():
    model = {
        "banks": {"A": {"records": [{"segments": []}]}, "B": {"records": []},
                  "C": {"records": [{"segments": []}, {"segments": []}]}},
        "sign_tables": {"LogicalSigns": []},
        "resources": {"Fonts": [], "Graphics": []},
        "db_frames": [],
        "effect_zones": [],
        "raw_mtu": b"class-counts",
        "class_c_profile": "legacy",
    }

    report = builder.preflight_model(model)

    assert report["message_records"] == 3
    assert report["message_classes"] == {"A": 1, "C": 2}


def test_preflight_categorizes_fonts_and_graphics():
    model = {
        "banks": {},
        "sign_tables": {"LogicalSigns": []},
        "resources": {
            "Fonts": [{"FontID": 1}, {"FontID": 2}],
            "Graphics": [
                {"GraphicID": 1, "RedGraphicBlobHex": None,
                 "GreenGraphicBlobHex": None, "BlueGraphicBlobHex": None},
                {"GraphicID": 2, "RedGraphicBlobHex": "aa",
                 "GreenGraphicBlobHex": "bb", "BlueGraphicBlobHex": "cc"},
            ],
        },
        "db_frames": [],
        "effect_zones": [],
        "raw_mtu": b"resource-categories",
        "class_c_profile": "legacy",
    }

    report = builder.preflight_model(model, known_font_ids={1})

    assert report["font_categories"] == {"known": 1, "unknown": 1}
    assert report["graphic_categories"] == {"colored": 1, "monochrome": 1}

    unclassified = builder.preflight_model(model)

    assert unclassified["font_categories"] == {"known": None, "unknown": None}


def test_class_message_element_rows_normalizes_class_a_title_for_compiler():
    classes = {
        "ClassAMsgs": [{
            "MsgCode": 500, "MsgClassID": 1, "Approved": True,
            "Title": "graphic", "IDTitle": 1, "Text": "", "IDText": 2,
        }],
        "ClassBMsgs": [],
        "ClassCMsgs": [],
    }

    rows = builder.class_message_element_rows(classes, "legacy")

    assert rows == [{
        "MsgCode": 500, "MsgClassID": 1, "ElementID": 1,
        "ElementText": "graphic", "Approved": True,
    }]


def test_class_message_element_rows_keep_all_expanded_class_c_elements():
    classes = {
        "ClassAMsgs": [],
        "ClassBMsgs": [],
        "ClassCMsgs": [{
            "MsgCode": 2, "MsgClassID": 3, "Approved": True,
            "Route": "2", "IDRoute": 6,
            "DestinationTop": "TOP", "IDDestinationTop": 14,
            "DestinationBot": "BOTTOM", "IDDestinationBot": 15,
            "DestinationSide": "SIDE", "IDDestinationSide": 16,
            "RouteSide": "2", "IDRouteSide": 17,
        }],
    }

    rows = builder.class_message_element_rows(classes, "expanded")

    assert [(row["MsgClassID"], row["MsgCode"], row["ElementID"]) for row in rows] == [
        (3, 2, 6), (3, 2, 14), (3, 2, 15), (3, 2, 16), (3, 2, 17),
    ]


def test_class_message_rows_reassembles_split_class_a_title():
    model = {
        "frames": [
            {"MsgClassID": 1, "MsgCode": 500, "LSignID": 2, "Frame": 1,
             "Phrase": "SECOND", "XPos": 1, "YPos": 1},
            {"MsgClassID": 1, "MsgCode": 500, "LSignID": 1, "Frame": 2,
             "Phrase": " WORLD", "XPos": 1, "YPos": 1},
            {"MsgClassID": 1, "MsgCode": 500, "LSignID": 1, "Frame": 1,
             "Phrase": "HELLO", "XPos": 1, "YPos": 1},
        ],
        "sign_tables": {},
        "class_c_profile": "legacy",
    }

    rows = builder.class_message_rows(model)

    assert rows["ClassAMsgs"] == [{
        "MsgCode": 500, "MsgClassID": 1, "Approved": True,
        "Title": "HELLO WORLD", "IDTitle": 1, "Text": "", "IDText": 2,
    }]
