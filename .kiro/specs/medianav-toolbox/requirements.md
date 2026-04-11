# Requirements: MediaNav Toolbox (Python)

## Overview

A Python CLI application that replicates the core functionality of the Dacia MediaNav Evolution Toolbox — communicating with the NaviExtras API to download map/content updates and install them onto a USB drive for use with Dacia MediaNav head units.

## Background

The original Windows application (`DaciaMediaNavEvolutionToolbox.exe`) is a CEF-based desktop app built on the `nngine.dll` engine. It communicates with `zippy.naviextras.com` to authenticate devices, fetch available content catalogs, download updates, and write them to USB drives. Our Python tool replaces this with a cross-platform CLI.

### Original App Architecture (from reverse engineering)
- **plugin.dll**: Configuration — API URLs, brand identity (`DaciaAutomotive`), channel (`linefit-dacia-nq`), registry paths
- **nngine.dll**: Core engine — HTTP communication, boot/catalog services, market API, download manager, synctool, fingerprint handling, device management
- **mtp.dll**: MTP device communication (file get/put/remove over USB MTP protocol)
- **DaciaMediaNavEvolutionToolbox.exe**: CEF shell hosting the web UI

### API Endpoints Discovered
- Boot/Index: `https://zippy.naviextras.com/services/index/rest`
- Self-update: `https://zippy.naviextras.com/services/selfie/rest/1/update`
- Dev endpoint: `http://zippy.dev.naviextras.com/services/index/rest/{version}/boot`

### Market API Calls (from nngine.dll)
- `LOGIN` — Authenticate with the service
- `GET_PROCESS` — Get the current update process/available content
- `SEND_DRIVES` — Report connected USB drives to the server
- `SEND_FINGERPRINT` — Send device fingerprint for identification
- `SEND_BACKUPS` — Send backup information
- `SEND_REPLACEMENT_DRIVES` — Report replacement drives
- `SEND_PROCESS_STATUS` — Report installation progress
- `SEND_DEVICE_STATUS` — Report device connection status
- `SEND_ERROR` — Report errors to server
- `SEND_SGN_FILE_VALIDITY` — Validate signature files
- `SEND_FILE_CONTENT` — Send file content (e.g., device.nng)

### Device Identification
- `device.nng` file on USB root — contains device identity, BrandMD5
- Fingerprint files in `fingerprints/` directory on USB
- Synctool checksum and drive info files for validation

### Content Types
- Maps (CITYMAP)
- POI (Points of Interest)
- Speed cameras / safety cameras
- Voices (TTS/guidance)
- 3D buildings

---

## User Stories

### US-1: Device Detection
**As a** user with a MediaNav USB drive plugged in,
**I want** the tool to detect and read the device identity from the USB,
**so that** I can see what device/head unit the USB belongs to.

#### Acceptance Criteria
- WHEN a USB drive containing `device.nng` is specified THE SYSTEM SHALL parse the device identity (BrandMD5, device info)
- WHEN no `device.nng` is found at the specified path THE SYSTEM SHALL display an error indicating the drive is not a valid MediaNav drive
- WHEN the `device.nng` file is corrupt or unreadable THE SYSTEM SHALL display a meaningful error message
- THE SYSTEM SHALL support specifying the USB mount path via CLI argument

### US-2: API Authentication (Boot & Catalog)
**As a** user,
**I want** the tool to authenticate with the NaviExtras API,
**so that** I can access the content catalog for my device.

#### Acceptance Criteria
- WHEN a valid device identity is loaded THE SYSTEM SHALL call the boot service at `https://zippy.naviextras.com/services/index/rest` to obtain the index/catalog service URLs
- WHEN the boot service responds THE SYSTEM SHALL parse the response to extract the catalog endpoint and session parameters
- WHEN the boot service fails THE SYSTEM SHALL retry up to 3 times before reporting an error
- THE SYSTEM SHALL send the device fingerprint as part of the authentication flow
- THE SYSTEM SHALL support the `service_boot_v3` and `service_catalog_v3` protocol versions

### US-3: Content Catalog Browsing
**As a** user,
**I want** to see what content updates are available for my device,
**so that** I can choose what to download.

#### Acceptance Criteria
- WHEN authenticated THE SYSTEM SHALL fetch the content catalog via the catalog service
- WHEN the catalog is received THE SYSTEM SHALL display available updates grouped by content type (maps, POI, speedcams, voices)
- WHEN displaying content THE SYSTEM SHALL show: content name, type, size, and whether it's an update or new content
- THE SYSTEM SHALL indicate which content is already installed on the USB drive

### US-4: Content Download
**As a** user,
**I want** to download selected content updates,
**so that** I can install them on my USB drive.

#### Acceptance Criteria
- WHEN the user selects content for download THE SYSTEM SHALL execute the `LOGIN` → `SEND_DRIVES` → `SEND_FINGERPRINT` → `GET_PROCESS` market API flow
- WHEN downloading THE SYSTEM SHALL show progress (percentage, speed, ETA)
- WHEN a download is interrupted THE SYSTEM SHALL support resuming from where it left off (using Content-Range)
- WHEN a download completes THE SYSTEM SHALL verify the file integrity using MD5 checksums
- THE SYSTEM SHALL manage a local download cache at a configurable path
- WHEN the download cache already contains a valid file THE SYSTEM SHALL skip re-downloading it

### US-5: USB Content Installation
**As a** user,
**I want** downloaded content to be installed onto my USB drive,
**so that** my MediaNav head unit can use the updates.

#### Acceptance Criteria
- WHEN content is downloaded and verified THE SYSTEM SHALL install it to the correct directory structure on the USB drive
- WHEN installing THE SYSTEM SHALL preserve the synctool-compatible file layout expected by the head unit
- WHEN installing THE SYSTEM SHALL update fingerprint files and checksums on the USB drive
- WHEN the USB drive has insufficient space THE SYSTEM SHALL warn the user before attempting installation
- THE SYSTEM SHALL report installation progress via `SEND_PROCESS_STATUS` to the API

### US-6: Fingerprint Management
**As a** user,
**I want** the tool to manage device fingerprints correctly,
**so that** the API recognises my device and provides the right content.

#### Acceptance Criteria
- WHEN a USB drive is detected THE SYSTEM SHALL read existing fingerprints from the `fingerprints/` directory
- WHEN fingerprints need updating THE SYSTEM SHALL generate and save new fingerprints in the correct format
- WHEN sending fingerprints to the API THE SYSTEM SHALL encode them as expected by the `SEND_FINGERPRINT` market call
- THE SYSTEM SHALL validate fingerprint integrity (MD5 match, presence of checksum and drive info files)

### US-7: Configuration & CLI Interface
**As a** user,
**I want** a clear CLI interface with sensible defaults,
**so that** I can use the tool without deep knowledge of the API.

#### Acceptance Criteria
- THE SYSTEM SHALL provide the following CLI commands:
  - `detect <usb_path>` — Detect and display device info from USB
  - `catalog <usb_path>` — Show available content updates
  - `download <usb_path> [--content-id ID]` — Download content updates
  - `install <usb_path>` — Install downloaded content to USB
  - `sync <usb_path>` — Full flow: detect → catalog → download → install
- THE SYSTEM SHALL store configuration (cache path, API URLs) in a config file
- THE SYSTEM SHALL support `--verbose` / `-v` flag for debug output
- THE SYSTEM SHALL use the production API URL by default: `https://zippy.naviextras.com/services/index/rest`

### US-8: Error Handling & Logging
**As a** user,
**I want** clear error messages and logging,
**so that** I can troubleshoot issues.

#### Acceptance Criteria
- WHEN an API call fails THE SYSTEM SHALL display the error code and a human-readable message
- WHEN a network error occurs THE SYSTEM SHALL retry with exponential backoff (max 3 retries)
- THE SYSTEM SHALL log all API interactions when verbose mode is enabled
- THE SYSTEM SHALL report errors to the API via `SEND_ERROR` market call (matching original app behaviour)

---

## Non-Functional Requirements

### NFR-1: Cross-Platform
- THE SYSTEM SHALL run on Linux, macOS, and Windows
- THE SYSTEM SHALL use Python 3.10+ with no platform-specific dependencies for core functionality

### NFR-2: Performance
- THE SYSTEM SHALL support concurrent downloads (configurable, default 2)
- THE SYSTEM SHALL use streaming downloads to avoid loading large files into memory

### NFR-3: Security
- THE SYSTEM SHALL communicate with the API over HTTPS only
- THE SYSTEM SHALL NOT store user credentials on disk
- THE SYSTEM SHALL validate SSL certificates

### NFR-4: Compatibility
- THE SYSTEM SHALL produce USB drive layouts compatible with the original Dacia MediaNav Evolution Toolbox
- THE SYSTEM SHALL support the same `device.nng` format as the original application
