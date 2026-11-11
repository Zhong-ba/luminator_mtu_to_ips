"""Class C (destination) authoring elements: layout model and frame decoding.

A compiled MTU keeps only what each sign displays.  IPS element names, listing
columns, listing text and each frame's ElementID are authoring metadata that
the compiler discards, so they are reconstructed here from cross-sign
structure:

* the rear sign shows the route number, which identifies route text elsewhere;
* on front-family signs the top line is the main destination and a lower line
  in a different font is the secondary destination;
* side and rear signs fill their own elements when those are chosen, and
  otherwise share the front elements they repeat.

The user chooses which elements exist (``ClassCLayout``).  Unchosen elements
fold into their parent (e.g. RouteSide -> RouteFront, MainSide -> MainFront).
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

ELEMENTS = ("RouteFront", "MainFront", "SecondaryFront", "RouteSide", "MainSide", "RouteRear")
REQUIRED_ELEMENTS = ("MainFront",)
# Stable IDs: 6/7 match IPS's stock Route/Destination elements; the rest avoid
# the IDs IPS uses for classes A, B, D and E.
ELEMENT_IDS = {"RouteFront": 6, "MainFront": 7, "SecondaryFront": 14,
               "RouteSide": 15, "MainSide": 16, "RouteRear": 17}
ELEMENT_DESCRIPTIONS = {
    "RouteFront": "Front route number", "MainFront": "Main front destination",
    "SecondaryFront": "Secondary front destination", "RouteSide": "Side route number",
    "MainSide": "Side destination", "RouteRear": "Rear route number",
}
ELEMENT_COLUMN_WIDTHS = {"RouteFront": 1200, "MainFront": 3000, "SecondaryFront": 3000,
                         "RouteSide": 1200, "MainSide": 3000, "RouteRear": 1200}
FALLBACK = {"SecondaryFront": "MainFront", "RouteSide": "RouteFront", "MainSide": "MainFront",
            "RouteRear": "RouteFront", "RouteFront": "MainFront"}
SIDE_ELEMENTS = ("RouteSide", "MainSide")
ROUTE_ELEMENTS = ("RouteFront", "RouteSide", "RouteRear")

FRAME_SEPARATOR = "^"
LINE_SEPARATOR = "\u00f7"  # IPS listing line break inside one frame
_LINE_GAP = 4               # pixels; smaller vertical offsets are the same text line
_ROUTE_TOKEN = re.compile(r"^[A-Z]{0,3}\d{1,4}[A-Z]{0,3}$")


@dataclass(frozen=True)
class ClassCLayout:
    """Which Class C elements the recovered project has.

    A chosen side or rear element is always filled from its signs; unchosen
    ones fold into the front element they would otherwise repeat.
    """
    elements: tuple[str, ...]

    def __post_init__(self):
        chosen = set(self.elements)
        unknown = chosen - set(ELEMENTS)
        if unknown:
            raise ValueError("Unknown Class C element(s): " + ", ".join(sorted(unknown))
                             + ". Choose from " + ", ".join(ELEMENTS))
        missing = [name for name in REQUIRED_ELEMENTS if name not in chosen]
        if missing:
            raise ValueError("Class C layout must include " + ", ".join(missing))
        object.__setattr__(self, "elements", tuple(name for name in ELEMENTS if name in chosen))

    @classmethod
    def parse(cls, text: str) -> "ClassCLayout":
        names = [part.strip() for part in re.split(r"[,;\s]+", text or "") if part.strip()]
        lookup = {name.lower(): name for name in ELEMENTS}
        resolved = []
        for name in names:
            if name.lower() not in lookup:
                raise ValueError(f"Unknown Class C element {name!r}. Choose from " + ", ".join(ELEMENTS))
            resolved.append(lookup[name.lower()])
        return cls(tuple(resolved))

    def resolve(self, element: str) -> str:
        while element not in self.elements:
            element = FALLBACK[element]
        return element

    # Layout interface shared with CustomLayout.
    @property
    def role_layout(self) -> "ClassCLayout":
        return self

    def name_for(self, role: str, sign_key: str) -> str:
        return role

    def primary_role(self, name: str) -> str:
        return name

    def element_id(self, name: str) -> int:
        return ELEMENT_IDS[name]

    def element_rows(self) -> list[dict]:
        return [{"ElementID": self.element_id(name), "MsgClassID": 3, "ElementName": name,
                 "ElementDescription": ELEMENT_DESCRIPTIONS[name]} for name in self.elements]

    def listing_columns(self) -> list[tuple[str, int]]:
        return ([("MsgCode", 900), ("Locked", 700)]
                + [(name, ELEMENT_COLUMN_WIDTHS[name]) for name in self.elements])

    def describe(self) -> dict:
        return {"elements": list(self.elements)}


CUSTOM_ELEMENT_FIRST_ID = 20   # above the IDs stock IPS projects use for any class
_ELEMENT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,29}")
_RESERVED_COLUMNS = {"msgcode", "msgclassid", "approved", "locked"}
PRESET_FORMAT = "luminator-mtu-to-ips/class-c-preset"
# Custom-layout choice for text kept on the signs but linked to no element
# (ElementID 0), as IPS authors do for text edited directly on a sign.
UNLINKED = "(unlinked)"


def validate_element_names(names) -> None:
    """Element names become ClassCMsgs columns (<name> and ID<name>)."""
    seen = {}
    for name in names:
        if not _ELEMENT_NAME.fullmatch(name or ""):
            raise ValueError(f"Invalid element name {name!r}: use 1-30 letters, digits or _, "
                             "starting with a letter")
        if name.lower() in _RESERVED_COLUMNS:
            raise ValueError(f"Element name {name!r} is reserved by IPS")
        if name.lower() in seen:
            raise ValueError(f"Element names {seen[name.lower()]!r} and {name!r} differ only by case")
        seen[name.lower()] = name
    for name in names:
        if ("id" + name).lower() in seen:
            raise ValueError(f"Element {seen[('id' + name).lower()]!r} clashes with the ID column of {name!r}")


@dataclass(frozen=True)
class CustomLayout:
    """User-named elements, assigned per (role, physical sign) group.

    ``assignments`` maps (role, sign key) to an element name; groups not listed
    use ``role_defaults`` so a preset also applies to MTUs with other signs.
    Giving several groups one name merges them into a single element.
    """
    assignments: tuple[tuple[str, str, str], ...]
    role_defaults: tuple[tuple[str, str], ...]
    order: tuple[str, ...] = ()

    def __post_init__(self):
        defaults = dict(self.role_defaults)
        missing = [role for role in ELEMENTS if role not in defaults]
        if missing:
            raise ValueError("Custom layout needs a default element for " + ", ".join(missing))
        bad_roles = {role for role, _, _ in self.assignments} - set(ELEMENTS)
        if bad_roles:
            raise ValueError("Unknown role(s): " + ", ".join(sorted(bad_roles)))
        used = list(dict.fromkeys(
            [name for _, _, name in self.assignments] + [defaults[role] for role in ELEMENTS]))
        used = [name for name in used if name != UNLINKED]
        if not used:
            raise ValueError("Keep at least one element; every group is unlinked")
        order = [name for name in dict.fromkeys(self.order) if name in used]
        # Unordered names follow their first role in ELEMENTS order.
        order += sorted((name for name in used if name not in order),
                        key=lambda name: ELEMENTS.index(self._first_role(name)))
        validate_element_names(order)
        object.__setattr__(self, "order", tuple(order))
        object.__setattr__(self, "_lookup", {(role, sign): name for role, sign, name in self.assignments})
        object.__setattr__(self, "_defaults", defaults)

    @classmethod
    def build(cls, assignments: dict[tuple[str, str], str], order=None) -> "CustomLayout":
        """Create a layout from per-group names.

        A role's default (used for signs not in ``assignments``) is its most
        common chosen name; roles with no groups fold into their parent role's
        default so they do not add empty elements.
        """
        chosen = {}
        for role in ELEMENTS:
            names = Counter(name for (group_role, _), name in assignments.items() if group_role == role)
            if names:
                chosen[role] = names.most_common(1)[0][0]
        defaults = {}
        for role in ELEMENTS:
            parent = role
            while parent not in chosen and parent in FALLBACK:
                parent = FALLBACK[parent]
            defaults[role] = chosen.get(parent, parent)
        return cls(tuple((role, sign, name) for (role, sign), name in sorted(assignments.items())),
                   tuple(defaults.items()), tuple(order or ()))

    def _first_role(self, name: str) -> str:
        roles = [role for role, _, n in self.assignments if n == name]
        roles += [role for role, n in self.role_defaults if n == name]
        return min(roles, key=ELEMENTS.index) if roles else "MainFront"

    @property
    def elements(self) -> tuple[str, ...]:
        return self.order

    @property
    def role_layout(self) -> ClassCLayout:
        return ClassCLayout(ELEMENTS)

    def name_for(self, role: str, sign_key: str) -> str:
        return self._lookup.get((role, sign_key), self._defaults[role])

    def primary_role(self, name: str) -> str:
        return self._first_role(name)

    def element_id(self, name: str) -> int:
        # Numbered in output order so every IPS view of the elements agrees with it.
        return CUSTOM_ELEMENT_FIRST_ID + self.order.index(name)

    def element_rows(self) -> list[dict]:
        rows = []
        for name in self.order:
            role = self.primary_role(name)
            description = (ELEMENT_DESCRIPTIONS[name] if name in ELEMENT_DESCRIPTIONS
                           else f"Custom ({ELEMENT_DESCRIPTIONS[role].lower()})")
            rows.append({"ElementID": self.element_id(name), "MsgClassID": 3, "ElementName": name,
                         "ElementDescription": description})
        return rows

    def listing_columns(self) -> list[tuple[str, int]]:
        return ([("MsgCode", 900), ("Locked", 700)]
                + [(name, ELEMENT_COLUMN_WIDTHS[self.primary_role(name)]) for name in self.order])

    def describe(self) -> dict:
        return {"elements": list(self.order), "custom": True}

    def to_preset(self) -> dict:
        return {
            "format": PRESET_FORMAT, "version": 1,
            "elements": list(self.order),
            "role_defaults": dict(self.role_defaults),
            "assignments": [{"role": role, "sign": sign, "element": name}
                            for role, sign, name in self.assignments],
        }

    @classmethod
    def from_preset(cls, data: dict) -> "CustomLayout":
        if data.get("format") != PRESET_FORMAT:
            raise ValueError("Not a Class C element preset")
        return cls(tuple((a["role"], a["sign"], a["element"]) for a in data.get("assignments", [])),
                   tuple(dict(data.get("role_defaults", {})).items()),
                   tuple(data.get("elements", ())))


def save_preset(layout: CustomLayout, path) -> None:
    import json
    from pathlib import Path
    Path(path).write_text(json.dumps(layout.to_preset(), indent=2), encoding="utf-8")


def load_preset(path) -> CustomLayout:
    import json
    from pathlib import Path
    return CustomLayout.from_preset(json.loads(Path(path).read_text(encoding="utf-8")))


@dataclass
class SignGroups:
    front: list[int]   # canonical-first priority order (matrix fronts, then ODK)
    side: list[int]    # canonical-first
    rear: list[int]    # route-number displays; multi-vehicle MTUs may have several


_CHAR_PARTS = {"0100", "0101", "0102", "0103"}
_REAR_MAX_WIDTH = 48   # 48x16 rear, 40x12, 30x10, 30x7, 23x7 route boxes
_SIDE_MAX_HEIGHT = 8   # 96x8, 90x7, 64x8, 60x7 side displays


def sign_groups(sign_tables: dict | None) -> SignGroups:
    """Classify signs by display geometry, which is stable across part families.

    A single MTU may serve several vehicle types (e.g. 08Bx and 04xx sign sets),
    so any number of front, side and rear displays is allowed.  Large "Titan
    side" displays (112x14) carry a front-style route + destination layout and
    belong to the front family.
    """
    phys = {int(p["PSignID"]): p for p in (sign_tables or {}).get("PhysicalSigns", [])}
    fronts, odks, sides, rears = [], [], [], []
    for link in (sign_tables or {}).get("LogicalSignBuild", []):
        lid = int(link["LSignID"])
        p = phys.get(int(link["PSignID"]), {})
        part = str(p.get("PSignPartNumber") or "").upper()
        width = int(p.get("LogicalDotWidth") or p.get("PSignDotWidth") or 0)
        height = int(p.get("LogicalDotHeight") or p.get("PSignDotHeight") or 0)
        if str(p.get("PSignType") or "").lower() == "char" or part in _CHAR_PARTS:
            odks.append(lid)
        elif 0 < width <= _REAR_MAX_WIDTH:
            rears.append((-width * height, lid))
        elif 0 < height <= _SIDE_MAX_HEIGHT:
            sides.append((-width * height, lid))
        else:
            # The canonical front is the widest standard 16-dot display; it
            # carries the fullest wording (e.g. 160x16 over an abbreviated 112x16).
            fronts.append((height != 16, -width * height, lid))
    return SignGroups(front=[x[-1] for x in sorted(fronts)] + odks,
                      side=[x[-1] for x in sorted(sides)],
                      rear=[x[-1] for x in sorted(rears)])


@dataclass
class ClassCDecoding:
    layout: "ClassCLayout | CustomLayout"
    element_of: dict[int, str | None]          # frame ordinal -> element name (None: graphic or unlinked)
    listings: dict[int, dict[str, str]]        # MsgCode -> element name -> listing text
    usage: Counter = field(default_factory=Counter)  # element -> number of messages using it
    # side/rear element -> messages where those signs differ from the front
    needed: Counter = field(default_factory=Counter)
    role_of: dict[int, str] = field(default_factory=dict)  # frame ordinal -> role before naming

    def element_id(self, ordinal: int) -> int:
        name = self.element_of.get(ordinal)
        return self.layout.element_id(name) if name else 0


@dataclass
class _Item:
    ordinal: int
    lid: int
    frame: int
    x: int
    y: int
    font: object
    centered: bool
    text: str
    norm: str
    slot: str = ""
    element: str = ""


def _norm(text: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (text or "").upper())


def _related(a: str, b: str) -> bool:
    """Exact or containment match, tolerant of graphics replacing letters."""
    if a == b:
        return bool(a)
    return min(len(a), len(b)) >= 4 and (a in b or b in a)


def _short_run(text: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9]{1,3}", text.strip()))


def _route_candidates(items: list[_Item]):
    """Yield single items and left-to-right runs of short glyph pieces.

    The compiler emits mixed-font route tokens as separate pieces that are
    horizontally adjacent but not on one baseline (N + 1, 12 + superscript S).
    """
    for index in range(len(items)):
        yield [index]
    order = sorted(range(len(items)), key=lambda i: (items[i].x, items[i].y))
    for pos, start in enumerate(order):
        group = [start]
        for following in order[pos + 1:pos + 3]:
            previous, current = items[group[-1]], items[following]
            if (not _short_run(previous.text) or not _short_run(current.text)
                    or abs(current.y - previous.y) > 2 * _LINE_GAP):
                break
            group.append(following)
            yield list(group)


def _mark_routes(items: list[_Item], route_norms: set[str]) -> None:
    """Mark items (or glyph runs) whose text is a known route value.

    A route occupies the top line of its frame; matching text on a lower line is
    part of the destination (e.g. a rear that cycles through the destination).
    """
    if not route_norms:
        return
    top = min(it.y for it in items)
    raw = set()
    for group in _route_candidates(items):
        if "".join(items[i].norm for i in group) in route_norms:
            raw.update(group)
    on_top = {i for i in raw if items[i].y - top < _LINE_GAP}
    # Lower pieces belong to the route only as glyph runs of a top-line route
    # token (a superscript S beside 12).
    hits = on_top | {i for i in raw - on_top if _short_run(items[i].text)
                     and any(_short_run(items[j].text) for j in on_top)}
    # A frame showing nothing but the route value is a destination, not a route.
    if hits and len(hits) < len(items):
        for index in hits:
            items[index].slot = "route"


def _structural_route_norms(frames: dict[int, list[_Item]]) -> set[str]:
    """Without a rear sign, a route is a route-like token shown beside other text.

    The token may sit at either edge and may be split into glyph runs.  It must
    recur in every frame that has more than one text item, so a single numeric
    word inside a destination is not mistaken for a route.
    """
    per_frame = []
    for items in frames.values():
        if len(items) < 2:
            continue
        tokens = set()
        for group in _route_candidates(items):
            joined = "".join(items[i].norm for i in group)
            first = items[group[0]]
            others = [it for index, it in enumerate(items) if index not in group]
            # A letter-only badge (C, IGL) counts when the rest of the frame sits
            # lower, i.e. is vertically centred in a smaller font beside it.
            badge = (bool(re.fullmatch(r"[A-Z]{1,3}", joined)) and not first.centered
                     and all(it.y > first.y and it.x > first.x for it in others))
            if ((_ROUTE_TOKEN.match(joined) or badge)
                    and (len(group) > 1 or not first.centered)):
                tokens.add(joined)
        per_frame.append(tokens)
    return set.intersection(*per_frame) if per_frame else set()


def _assign_lines(items: list[_Item]) -> None:
    rest = [it for it in items if it.slot != "route"]
    if not rest:
        return
    top = min(it.y for it in rest)
    top_fonts = {it.font for it in rest if it.y - top < _LINE_GAP}
    for it in rest:
        lower = it.y - top >= _LINE_GAP
        it.slot = "secondary" if lower and it.font not in top_fonts else "main"


def _decode_message(rows, groups: SignGroups, layout, sign_keys: dict[int, str], element_of: dict,
                    role_of: dict, needed: Counter) -> dict[str, str]:
    """Assign roles with ``layout.role_layout``, then name them through ``layout``."""
    roles = layout.role_layout
    signs: dict[int, dict[int, list[_Item]]] = defaultdict(lambda: defaultdict(list))
    frames_of: dict[int, set[int]] = defaultdict(set)
    graphic_frames: set[tuple[int, int]] = set()
    blanks: list[tuple[int, int]] = []
    for ordinal, row in rows:
        lid, frame = int(row["LSignID"]), int(row["Frame"])
        frames_of[lid].add(frame)
        if row.get("GraphicIndex") is not None:
            element_of[ordinal] = None
            graphic_frames.add((lid, frame))
            continue
        text = str(row.get("Phrase") or "")
        if not text:
            blanks.append((ordinal, lid))
            continue
        signs[lid][frame].append(_Item(
            ordinal, lid, frame, int(row.get("XPos") or 1), int(row.get("YPos") or 1),
            row.get("FontIndex"), bool(row.get("HJustify")), text, _norm(text)))
    for frames in signs.values():
        for items in frames.values():
            items.sort(key=lambda it: (it.y, it.x, it.ordinal))

    def items_of(lids):
        return [it for lid in lids if lid in signs for f in signs[lid].values() for it in f]

    front_lids = [lid for lid in groups.front if lid in signs]
    side_lids = [lid for lid in groups.side if lid in signs]
    rear_lids = [lid for lid in groups.rear if lid in signs]

    # 1. Routes: rear displays show the route; otherwise use the canonical front layout.
    route_norms = {it.norm for it in items_of(rear_lids)}
    route_norms.discard("")
    if not route_norms and front_lids:
        route_norms = _structural_route_norms(signs[front_lids[0]])
    for lid in front_lids + side_lids:
        for items in signs[lid].values():
            _mark_routes(items, route_norms)
            _assign_lines(items)

    # 2. Front family: non-canonical signs (ODK, Titan) follow canonical text.
    canonical = {}
    if front_lids:
        for it in items_of(front_lids[:1]):
            canonical.setdefault(it.norm, it.slot)
    for it in items_of(front_lids[1:]):
        match = canonical.get(it.norm)
        if match is None:
            match = next((slot for norm, slot in canonical.items() if _related(it.norm, norm)), None)
        if match is not None:
            it.slot = match
    front_slot_element = {"route": "RouteFront", "main": "MainFront", "secondary": "SecondaryFront"}
    for it in items_of(front_lids):
        it.element = roles.resolve(front_slot_element[it.slot])

    # 3. Side signs fill the chosen side elements.  An unchosen one falls back to
    # the front element showing the same text, then to its parent element.
    front_norms = {}
    for it in items_of(front_lids):
        front_norms.setdefault(it.norm, it.element)
    for lid in side_lids:
        sign_items = items_of([lid])
        if not all(it.norm in front_norms for it in sign_items):
            needed.update(["MainSide"] + (["RouteSide"] if any(it.slot == "route" for it in sign_items) else []))
        for it in sign_items:
            target = "RouteSide" if it.slot == "route" else "MainSide"
            if target in roles.elements:
                it.element = target
            else:
                it.element = front_norms.get(it.norm) or roles.resolve(target)

    # 4. Rear displays fill RouteRear when chosen; otherwise they share the front
    # route they repeat.
    front_routes = {it.norm for it in items_of(front_lids) if it.slot == "route"}
    for it in items_of(rear_lids):
        if it.norm not in front_routes:
            needed["RouteRear"] += 1
        if "RouteRear" in roles.elements:
            choice = "RouteRear"
        elif not front_routes and "SecondaryFront" in roles.elements:
            # A rear message that is not a route number is the short destination.
            choice = "SecondaryFront"
        else:
            choice = "RouteFront"
        it.element = roles.resolve(choice)

    # Name each role through the layout (custom layouts split, merge or unlink
    # roles per sign; unlinked text stays on the sign with ElementID 0).
    for it in items_of(list(signs)):
        role_of[it.ordinal] = it.element
        name = layout.name_for(it.element, sign_keys.get(it.lid, ""))
        it.element = None if name == UNLINKED else name

    # 5. Element per frame row; blank frames follow their sign's dominant
    # destination element (route elements only when the sign has nothing else).
    per_sign = defaultdict(Counter)
    per_sign_routes = defaultdict(Counter)
    for lid, frames in signs.items():
        for items in frames.values():
            for it in items:
                element_of[it.ordinal] = it.element
                if it.element is not None:
                    target = per_sign_routes if role_of[it.ordinal] in ROUTE_ELEMENTS else per_sign
                    target[lid][it.element] += 1
    for ordinal, lid in blanks:
        common = per_sign[lid].most_common(1) or per_sign_routes[lid].most_common(1)
        fallback = layout.name_for(roles.resolve("MainFront"), sign_keys.get(lid, ""))
        element_of[ordinal] = common[0][0] if common else (None if fallback == UNLINKED else fallback)

    # 6. Listing text, from the sign that best represents each element, so each
    # listing reflects the frames tagged with that element.
    listings = {}
    rear_source = groups.rear
    # A graphic may replace a letter (logo "V" + "AMOS"); other signs often show
    # the complete word, which is what the author typed.
    spelled = {}
    for it in items_of(list(signs)):
        spelled.setdefault(it.norm, it.text)
    for name in layout.elements:
        role = layout.primary_role(name)
        if role in SIDE_ELEMENTS:
            order = groups.side + groups.front
        elif role == "RouteRear":
            order = rear_source + groups.front + groups.side
        else:
            order = groups.front + groups.side + rear_source
        source = next((lid for lid in order if lid in signs and any(
            it.element == name for f in signs[lid].values() for it in f)), None)
        if source is None:
            listings[name] = ""
            continue

        def full_text(it: _Item, source=source) -> str:
            if (source, it.frame) not in graphic_frames or len(it.norm) < 3:
                return it.text
            longer = [text for norm, text in spelled.items()
                      if norm != it.norm and norm.endswith(it.norm) and len(norm) - len(it.norm) <= 2]
            return min(longer, key=len) if longer else it.text

        listings[name] = _listing_text(signs[source], frames_of[source], name, full_text)
    return listings


def _listing_text(frames: dict[int, list[_Item]], frame_numbers: set[int], element: str,
                  text_of=lambda it: it.text) -> str:
    values = []
    for frame in sorted(frame_numbers):
        lines: list[list[_Item]] = []
        for it in frames.get(frame, []):
            if it.element != element:
                continue
            if lines and it.y - lines[-1][0].y < _LINE_GAP:
                lines[-1].append(it)
            else:
                lines.append([it])
        text = ""
        previous = None
        for line in lines:
            for index, it in enumerate(sorted(line, key=lambda it: it.x)):
                piece = text_of(it)
                if previous is not None:
                    # Short glyph runs of a route token (N + 1, 12 + S) are one
                    # compiled token; destination words keep their separators.
                    route_piece = element in ROUTE_ELEMENTS or (previous.slot == "route" and it.slot == "route")
                    if route_piece and _short_run(text_of(previous)) and _short_run(piece):
                        separator = ""
                    else:
                        separator = " " if index else LINE_SEPARATOR
                    text += separator
                text += piece
                previous = it
        values.append(text)
    while values and not values[-1]:
        values.pop()
    while values and not values[0]:
        values.pop(0)
    return FRAME_SEPARATOR.join(values)


def decode_class_c(frames: list[dict], sign_tables: dict | None,
                   layout: "ClassCLayout | CustomLayout") -> ClassCDecoding:
    """Assign an element to every Class C frame row and rebuild listing text."""
    groups = sign_groups(sign_tables)
    by_code = defaultdict(list)
    for ordinal, row in enumerate(frames):
        if int(row.get("MsgClassID", 0)) == 3:
            by_code[int(row["MsgCode"])].append((ordinal, row))
    element_of: dict[int, str | None] = {}
    role_of: dict[int, str] = {}
    listings: dict[int, dict[str, str]] = {}
    usage: Counter = Counter()
    needed: Counter = Counter()
    keys = sign_keys(sign_tables)
    for code, rows in sorted(by_code.items()):
        message_needs: Counter = Counter()
        listings[code] = _decode_message(rows, groups, layout, keys, element_of, role_of, message_needs)
        usage.update({element_of[o] for o, _ in rows if element_of.get(o)})
        needed.update(set(message_needs))
    return ClassCDecoding(layout, element_of, listings, usage, needed, role_of)


def sign_keys(sign_tables: dict | None) -> dict[int, str]:
    """Stable per-fleet sign identity (part number @ peripheral address)."""
    phys = {int(p["PSignID"]): p for p in (sign_tables or {}).get("PhysicalSigns", [])}
    return {int(link["LSignID"]): "{}@{}".format(
                str(phys.get(int(link["PSignID"]), {}).get("PSignPartNumber") or "?").upper(),
                link.get("PSignAddr"))
            for link in (sign_tables or {}).get("LogicalSignBuild", [])}


@dataclass
class ElementGroup:
    """One role on one physical sign: the unit a custom layout names."""
    role: str
    sign: str          # sign key, e.g. 08B1@2
    label: str         # human description of the sign
    kind: str          # front / side / rear / ODK
    messages: int
    rows: int
    samples: list[str]


def analyze_groups(frames: list[dict], sign_tables: dict | None, sample_count: int = 4) -> list[ElementGroup]:
    """Group Class C text by role and sign for naming custom elements."""
    decoding = decode_class_c(frames, sign_tables, ClassCLayout(ELEMENTS))
    groups = sign_groups(sign_tables)
    keys = sign_keys(sign_tables)
    phys = {int(p["PSignID"]): p for p in (sign_tables or {}).get("PhysicalSigns", [])}
    info = {}
    for link in (sign_tables or {}).get("LogicalSignBuild", []):
        p = phys.get(int(link["PSignID"]), {})
        lid = int(link["LSignID"])
        kind = ("rear" if lid in groups.rear else "side" if lid in groups.side
                else "ODK" if str(p.get("PSignType") or "").lower() == "char" else "front")
        size = f"{p.get('LogicalDotWidth') or p.get('PSignDotWidth')}x{p.get('LogicalDotHeight') or p.get('PSignDotHeight')}"
        info[lid] = (kind, f"{p.get('PSignName') or p.get('PSignPartNumber') or 'sign'} {size} {kind} @ {link.get('PSignAddr')}")
    order = {lid: index for index, lid in enumerate(groups.front + groups.side + groups.rear)}
    stats = defaultdict(lambda: {"messages": set(), "rows": 0, "texts": Counter()})
    for ordinal, role in decoding.role_of.items():
        row = frames[ordinal]
        stat = stats[(role, int(row["LSignID"]))]
        stat["messages"].add(int(row["MsgCode"]))
        stat["rows"] += 1
        stat["texts"][str(row.get("Phrase") or "")] += 1
    result = []
    for (role, lid), stat in sorted(stats.items(), key=lambda kv: (ELEMENTS.index(kv[0][0]), order.get(kv[0][1], 999))):
        kind, label = info.get(lid, ("front", f"sign {lid}"))
        result.append(ElementGroup(role, keys.get(lid, str(lid)), label, kind, len(stat["messages"]),
                                   stat["rows"], [text for text, _ in stat["texts"].most_common(sample_count)]))
    return result


def suggest_layout(frames: list[dict], sign_tables: dict | None) -> ClassCLayout:
    """Suggest the elements a project needs.

    Front elements are suggested when their content occurs; side and rear
    elements only when those signs show something different from the front,
    since otherwise they would just repeat front values.
    """
    full = decode_class_c(frames, sign_tables, ClassCLayout(ELEMENTS))
    messages = max(1, len(full.listings))
    threshold = max(2, round(messages * 0.02))
    counts = {name: full.needed[name] if name in SIDE_ELEMENTS + ("RouteRear",) else full.usage[name]
              for name in ELEMENTS}
    chosen = [name for name in ELEMENTS if name in REQUIRED_ELEMENTS or counts[name] >= threshold]
    if "RouteSide" in chosen and "MainSide" not in chosen:
        chosen.remove("RouteSide")
    return ClassCLayout(tuple(chosen))
