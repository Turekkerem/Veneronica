# Module: System Persistence and Masquerading

## Technical Description
This module automates system persistence establishment by leveraging native Windows registry run keys, execution options, and file staging techniques. It includes file masquerading behavior to blend dropped binaries with legitimate system process names.

## Mechanics
- **Process Masquerading:** The payload selects a randomized name mimicking essential Windows binaries (e.g., `svchost.exe`, `csrss.exe`) to blend into basic process audits.
- **File Staging & Hiding:** Depending on privileges, the binary copies itself to protected directories (`System32`) or user-space locations (`AppData`), subsequently applying the `FILE_ATTRIBUTE_HIDDEN` attribute.
- **Registry Hooking:** It iterates through predefined structural persistence vectors (such as `Run`, `Winlogon\Shell`, or `BootExecute`), randomly picking a vector matching the current security context and injecting the execution path.