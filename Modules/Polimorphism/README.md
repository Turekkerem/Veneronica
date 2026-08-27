What the Code Does (Practical Description)
Self-Renaming: Bypasses Windows file-lock restrictions by renaming its running executable to a temporary .tmp file.

Binary Loading: Reads its own compiled binary data from disk entirely into memory (RAM).

Marker Detection: Scans the binary buffer to locate a specific placeholder string (POLYMORPHIC01).

Data Mutation: Generates 1,000 fresh random numbers (using Windows CryptoAPI's CryptGenRandom or standard rand()) and overwrites the data block attached to the marker.

Hash Alteration: Saves the modified buffer back to disk under the original executable name, effectively changing the file's binary signature and cryptographic hash on every run.

Execution Output: Calculates the sum of the newly generated random numbers and displays them in a Windows message box.