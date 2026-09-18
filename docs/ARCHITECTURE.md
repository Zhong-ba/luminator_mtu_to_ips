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

## Class-C profiles

### Expanded

```text
Route
DestinationTop
DestinationBot
DestinationSide
RouteSide
```

### Legacy

```text
Route
Destination
SmallSide
```

The compiled MTU stores sign-specific rendered elements rather than database column labels. Reconstruction therefore uses sign roles, geometry, frame ordering, and cross-sign text relationships.

## Jet writing

The parser itself is platform-independent. The maintained writer uses Microsoft DAO/Jet on Windows because Luminator IPS projects use an old Jet database format and DAO provides the safest way to preserve schema behavior, AutoNumber handling, long binary fields, indexes, and relationships.
