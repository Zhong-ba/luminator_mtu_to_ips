# Architecture / format notes

## Pipeline

```text
MTU
 ├─ master table / section directory
 ├─ physical configuration
 ├─ sign/listing configuration
 ├─ fonts
 ├─ graphics
 └─ message banks A-K
        │
        ▼
normalized project model
        │
        ├─ PhysicalSigns / LogicalSigns
        ├─ MessageFrames / EffectZones
        ├─ Fonts / Graphics
        ├─ Class A/B/C listings
        └─ SignSetOutput = original MTU
        │
        ▼
copy donor Jet database
        │
        ▼
DAO inserts/remaps AutoNumbers
        │
        ▼
recovered .ips + verification JSON
```

## Sign selectors

Ordinary selectors are encoded as a page byte plus an 8-bit bitset. The decoder treats a selected bit as a physical peripheral address:

```text
0x0002 -> address 1
0x0101 -> address 8
0x0120 -> address 13
0x0140 -> address 14
```

`0xED` introduces an extended list of selector masks.

## Message controls

Known compiler controls include positioning, centering, fonts, graphics, timing, and sparse message-number jumps. Unknown controls are preserved and cause preflight failure rather than being silently discarded.

Examples of recovered semantics:

- `F3` extended signed pixel position
- `F4` normal pixel position
- `F5` character-cell positioning
- `F6` graphic selector
- `F7` font selector
- `F9` timing
- `F1` horizontal centering

The parser also handles implicit cursor advance based on compiled glyph widths and implicit matrix default fonts from the sign configuration.

## Class C elements

Element labels are not compiled into the MTU, so `class_c_elements.py` rebuilds them from cross-sign structure for the user-chosen layout (`RouteFront`, `MainFront`, `SecondaryFront`, `RouteSide`, `MainSide`, `RouteRear`).

Signs are grouped by display geometry, which is stable across part families (08Bx, 04xx) and works for MTUs that serve several vehicle types: displays at most 48 dots wide are rear/route displays (any number of them), displays at most 8 dots tall are sides, and the rest — including 112x14 "Titan side" displays — are front-family with the ODK last. The canonical front is the widest 16-dot display.

1. **Route**: text the rear displays show marks route items on the other signs, including split glyph runs such as `N` + `1` or a superscript `S`. A route starts on the top line of its frame, so matching text on a lower line stays destination. Without a rear sign, a route-like token (or a short letter badge beside lower, smaller text) repeated in every frame is used.
2. **Main / secondary**: on front-family signs the top non-route line is the main destination; a lower line in a different font is the secondary destination. Non-canonical front signs follow the canonical front's text where it matches.
3. **Side**: when chosen, `RouteSide`/`MainSide` are always filled from the side signs. When not chosen, side text takes the front element showing the same text, else the parent element.
4. **Rear**: when chosen, `RouteRear` is always filled from the rear displays. Otherwise a rear that is not a front route becomes the secondary destination when the front has no route, else `RouteFront`.
5. **Folding**: unchosen elements resolve to their parent (`RouteSide`/`RouteRear` → `RouteFront` → `MainFront`; `MainSide`/`SecondaryFront` → `MainFront`).

Suggestions check front elements whose content occurs, and side/rear elements only when those signs differ from the front in at least 2% of messages.

Graphics use ElementID 0 and blank frames take their sign's dominant element. Listing text joins frames with `^` and in-frame lines with `÷`. The writer makes `ClassCMsgs` hold exactly the chosen element columns (zero-length strings allowed) and leaves `ClassMsgs` empty, as native IPS projects do.

## Jet writing

The parser itself is platform-independent. The maintained writer uses Microsoft DAO/Jet on Windows because Luminator IPS projects use an old Jet database format and DAO provides the safest way to preserve schema behavior, AutoNumber handling, long binary fields, indexes, and relationships.
