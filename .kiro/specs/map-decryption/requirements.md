# Requirements: NNG Map File Decryption

## Overview

Decrypt and parse the proprietary NNG map files (`.fbl`, `.fpa`, `.hnr`, `.poi`, `.spc`)
used by the Dacia MediaNav head unit. These files are encrypted with an unknown algorithm
and contain OpenStreetMap-derived navigation data.

## Background

### What We Have
- 119 encrypted map files (3.1 GB) from `disk-backup-with-map-Apr2026.zip`
- The RSA public key for `.lyc` license decryption (2048-bit, extracted from `nngine.dll`)
- Working `.lyc` decryption: RSA PKCS#1 v1.5 → 40-byte header → XOR-CBC for remaining data
- The full `nngine.dll` (3.3 MB PE32) available for Ghidra analysis
- Magic bytes identified: FBL/FPA=`f96d4a166fc578ee`, HNR=`e2664c5034c27fce`, SPC=`0bf42d4b0fc37fce`
- OpenStreetMap source data freely available for cross-referencing

### What We Don't Have
- The decryption algorithm for map files
- The key source (from `.lyc`? from `device.nng`? hardcoded in DLL?)
- Any prior art — nobody has publicly reversed this

---

## User Stories

### US-1: Decrypt a Map File
**As a** researcher analysing the MediaNav system,
**I want** to decrypt an encrypted `.fbl` map file,
**so that** I can examine the internal data structure.

#### Acceptance Criteria
- WHEN given an encrypted `.fbl` file and the appropriate key material
  THE SYSTEM SHALL produce a decrypted output file
- WHEN the decryption is successful THE SYSTEM SHALL report reduced Shannon entropy
  (below 7.0 bits/byte, indicating non-random structured data)
- WHEN the decrypted output contains recognisable strings (road names, place names)
  THE SYSTEM SHALL confirm successful decryption
- WHEN given an incorrect key THE SYSTEM SHALL report that decryption failed
  (output entropy remains near 8.0)

### US-2: Identify the Encryption Algorithm
**As a** reverse engineer,
**I want** to determine how NNG encrypts map files,
**so that** I can implement decryption for any map file.

#### Acceptance Criteria
- THE SYSTEM SHALL document the encryption algorithm (cipher, mode, key derivation)
- THE SYSTEM SHALL document the key source (where the key comes from)
- THE SYSTEM SHALL verify the algorithm against at least 3 different country files
- THE SYSTEM SHALL handle all file types: `.fbl`, `.fpa`, `.hnr`, `.poi`, `.spc`

### US-3: Parse Decrypted Map Data
**As a** developer building map tools,
**I want** to parse the decrypted map data into a usable structure,
**so that** I can extract road networks, POIs, and speed cameras.

#### Acceptance Criteria
- WHEN given a decrypted `.fbl` file THE SYSTEM SHALL extract the bounding box
  (min/max latitude and longitude)
- WHEN given a decrypted `.fbl` file THE SYSTEM SHALL extract road segment count
- WHEN given a decrypted `.spc` file THE SYSTEM SHALL extract speed camera locations
  as (latitude, longitude, speed_limit, type) tuples
- WHEN given a decrypted `.poi` file THE SYSTEM SHALL extract POI entries as
  (latitude, longitude, name, category) tuples

### US-4: Export to Open Formats
**As a** user who wants to view map data,
**I want** to export decrypted map data to standard formats,
**so that** I can view it in GIS tools or web maps.

#### Acceptance Criteria
- WHEN given a decrypted `.fbl` file THE SYSTEM SHALL export road network as GeoJSON
- WHEN given a decrypted `.spc` file THE SYSTEM SHALL export speed cameras as CSV
- WHEN given a decrypted `.poi` file THE SYSTEM SHALL export POIs as KML or GeoJSON
- THE SYSTEM SHALL produce output viewable in QGIS, geojson.io, or Google Earth

---

## Non-Functional Requirements

### NFR-1: Correctness
- Decrypted coordinates SHALL match OpenStreetMap data for the same region
  (within 0.001° tolerance for spot checks)

### NFR-2: Performance
- Decryption of a 100 MB file SHALL complete in under 30 seconds on commodity hardware

### NFR-3: Tooling
- All tools SHALL be Python 3.13+ with no platform-specific dependencies
- Tools SHALL be in `tools/maps/` directory
- Tools SHALL be runnable standalone (no need to install the full medianav_toolbox package)
