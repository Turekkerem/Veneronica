# Module: File Timestamp Manipulation (Timestomping)

## Technical Description
This module performs programmatic mass file attribute tampering, commonly known as "timestomping." The objective is to manipulate file system metadata (creation, last access, and last modification timestamps) to disrupt forensic analysis, timeline reconstruction, and indicator-of-compromise correlation.

## Mechanics
- **Cryptographic Time Generation:** Generates synthetic, uniform random `FILETIME` structures spanning across a wide chronological range (1990–2030) using a 64-bit Mersenne Twister distribution engine (`std::mt19937_64`).
- **File System Traversal:** Recursively parses local mounted drives (`DRIVE_FIXED` and `DRIVE_REMOVABLE`) utilizing Win32 APIs (`FindFirstFileA` / `FindNextFileA`).
- **Metadata Overwrite:** Opens file handles via `CreateFileA` with `FILE_FLAG_BACKUP_SEMANTICS` (allowing directory handle manipulation) and applies artificial timestamps using `SetFileTime`.