# Voice File Tools

Tools for exploring, modifying, and creating MediaNav iGO voice guidance files.

## Background

MediaNav voice files are **zip archives** containing Lua scripts and configuration
that drive the iGO TTS (text-to-speech) engine. They are NOT audio recordings —
the navigation engine synthesises speech at runtime using a built-in TTS engine
(Loquendo 7 / Nuance Vocalizer).

**No DRM.** Voice files have no license requirement. They're plain `.zip` files
with no encryption or RSA signing.

## Voice File Structure

Each voice is a `.zip` file in `content/voice/` on the head unit:

```
Voice_Eng-uk-f3-lua.zip
├── info.ini                          # Voice metadata
├── config/
│   ├── config_transform_tables.lua   # Navigation phrase templates
│   ├── config_tts.lua                # TTS engine configuration
│   └── ...
├── dictionary/                       # Pronunciation dictionaries
│   └── *.dic
└── sounds/                           # Pre-recorded audio clips (optional)
    └── *.ogg or *.wav
```

### Naming Convention

`Voice_{Lang}-{variant}-lua.zip`

| Part | Meaning | Examples |
|------|---------|---------|
| Lang | Language code | `Eng-uk`, `Fra`, `Deu`, `Esp` |
| variant | Voice variant | `f3` (female 3), `m2` (male 2) |
| lua | Script type | Always `lua` for Lua-scripted TTS |

### info.ini

```ini
tts_engine=loquendo
language=English
country=UK
gender=female
name=Kate
```

### config_transform_tables.lua

This is the key file — it defines how navigation instructions are spoken.
It maps navigation events to text strings that the TTS engine speaks:

```lua
-- Example entries (from community research):
turn_left = "Turn left"
turn_right = "Turn right"
keep_left = "Keep left"
roundabout_exit_1 = "Take the first exit"
speed_warning = "You have passed the speed limit"
```

The file is **UTF-16 LE** encoded with BOM.

### TTS Engine

The MediaNav head unit uses **Loquendo 7** (now Nuance Vocalizer) as the TTS engine.
The engine is built into the iGO navigation software — it's not a separate app.

Both Loquendo 6 and 7 voice files work (confirmed by community). The `tts_engine`
field in `info.ini` selects the engine.

## Prior Art

The iGO modding community has successfully modified voice files:

- **GPSPower forum** — tutorials on editing `config_transform_tables.lua` to change
  what phrases are spoken (e.g., shorter speed warnings)
- **Loquendo 6/7 compatibility** — both engine versions work with newer iGO Primo
- **File editing** — standard zip tools (WinRAR, 7zip) work; files are UTF-16 LE
- **No signing required** — modified voice files work without any re-signing

**Nobody has created a completely new voice from scratch** — all modifications are
edits to existing voice files. Creating a new voice would require understanding the
full Lua TTS API.

## Goal

Generate audio output from navigation commands:

```bash
# Target usage:
python tools/voice/speak.py --voice Eng-uk-f3 "turn left"
# → outputs turn_left.wav

python tools/voice/speak.py --voice Eng-uk-f3 --instruction roundabout_exit_3
# → outputs "Take the third exit at the roundabout"
```

## Task List

### Phase 1: Extract and Understand

- [ ] **T1.** Extract a voice `.zip` from the head unit (not on USB — USB only has `.stm` shadow files). Need to either:
  - Mount the QEMU disk image and find the voice files
  - Or capture them during a Toolbox sync (they may be in the download cache)
- [ ] **T2.** Document the complete file listing inside a voice `.zip`
- [ ] **T3.** Parse `info.ini` — document all fields
- [ ] **T4.** Parse `config_transform_tables.lua` — extract all navigation phrase mappings
- [ ] **T5.** Parse `config_tts.lua` — understand TTS engine configuration
- [ ] **T6.** Identify all Lua API functions called by the scripts
- [ ] **T7.** Document the dictionary file format (`.dic` files)

### Phase 2: Build Tools

- [ ] **T8.** `extract_voice.py` — extract and list contents of a voice `.zip`
- [ ] **T9.** `parse_phrases.py` — parse `config_transform_tables.lua` and list all phrases
- [ ] **T10.** `list_instructions.py` — show all navigation instruction types with their text

### Phase 3: Generate Audio

- [ ] **T11.** Research if Loquendo/Nuance Vocalizer has a Linux-compatible TTS engine
- [ ] **T12.** If not, use an alternative TTS engine (piper, espeak, Google TTS) to generate audio
- [ ] **T13.** `speak.py` — take a navigation instruction, look up the phrase template, generate audio
- [ ] **T14.** Support all instruction types: turns, roundabouts, motorway, speed warnings, distances

### Phase 4: Create Custom Voices

- [ ] **T15.** Build a voice `.zip` from scratch using a modern TTS engine
- [ ] **T16.** Test on the head unit (via USB sync)
- [ ] **T17.** Document the minimum viable voice file (what files are required)

## Installed Voices (67 total, ~192 MB)

Arabic, Bulgarian, Croatian, Czech, Danish, Dutch, English (AU/UK), Estonian,
Finnish, French, German, Greek, Hebrew, Hindi, Hungarian, Indonesian, Italian,
Kazakh, Latvian, Lithuanian, Norwegian, Persian, Polish, Portuguese (BR/PT),
Romanian, Russian, Serbian, Slovak, Slovenian, Spanish, Swedish, Turkish, Ukrainian.

Each language has 1-2 variants (male/female).

## References

- [GPSPower: Primo 2.4 audio modification](https://www.gpspower.net/igo-tutorials/338639-primo-2-4-audio-modification.html) — editing config_transform_tables.lua
- [GPSPower: Audio files in nextgen](https://www.gpspower.net/igo-primo-nextgen-help-support/361037-audio-files-nextgen.html) — .wav works in NextGen
- [GPSPower: iGO NextGen Voices and Languages](https://www.gpspower.net/igo-nextgen-voices-languages.html) — community voice forum
- [Loquendo TTS User Guide](https://archive.org/stream/manualzilla-id-5920959/5920959_djvu.txt) — TTS engine documentation
