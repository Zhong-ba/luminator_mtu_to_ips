from pathlib import Path
import sys

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
