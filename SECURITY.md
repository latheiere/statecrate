# Security policy

StateCrate processes backup archives and signing keys, so parser, extraction,
signature, key-handling, and restoration defects may have security impact.

Please do not open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability reporting for the repository. Include the affected
version, the triggering archive or operation, the security boundary crossed,
and a minimal reproduction when it is safe to share one.

Security fixes are provided for the latest released minor version. Older
versions should be upgraded before a report is evaluated for backporting.

StateCrate archives are signed but not encrypted. Disclosure of readable
archive content is not an encryption failure because confidentiality is outside
the package's contract.
