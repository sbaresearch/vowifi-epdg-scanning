# VoWiFi ePDG Scanning

This artifact contains the source code necessary to run client- and server-side evaluation scripts for our VoWiFi security analysis.
While the scripts can be used to scan for various security parameters (e.g., ciphers), our evaluation focuses on the key exchange (i.e., the supported diffie-hellmann (DH) groups and the rekey-timings) that are used for the first (i.e., \textit{phase 1}) VoWiFi tunnel that is essential to the security of the overall communication.

## Client Side Configuration Extraction (Passive/Static Analysis)

The relevant instructions can be found in the [client-side](/client-side) subdirectory.

## Server Side ePDG Probing (Active/Dynamic Analysis)

The relevant instructions can be found in the [server-side](/server-side) subdirectory.
