# Detection Policy

BDFR Sentinel is an anti-malware and endpoint-security project. It is not an anti-piracy, DRM-enforcement, or software-license compliance product.

## Default behavior

The default policy treats these categories as non-actionable by themselves:

- `Crack`
- `LicenseBypass`

A file is not quarantined merely because it is classified as a crack, keygen, activator, or license-bypass tool.

This does **not** suppress independent malware findings. If the same file also matches a Trojan, ransomware, backdoor, spyware, rootkit, worm, or other malware detection, the malware detection remains actionable.

## Potentially unwanted applications

PUA/PUP detections remain configurable and are not ignored by default.

## External definition sources

BDFR Sentinel can ingest multiple definition formats through provider adapters. Sources must be used according to their license and redistribution terms.

Supported/targeted classes include:

- YARA rule packs
- ClamAV-compatible HDB hash databases
- ClamAV-compatible HSB SHA-256 hash databases
- Additional open or redistribution-permitted threat intelligence feeds
- Custom BDFR Sentinel rule packs

Proprietary vendor databases must not be copied, decrypted, redistributed, or reverse-engineered solely to bypass their licensing or access controls.
