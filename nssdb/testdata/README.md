# Testdata

The directories contain NSS sqlite certificate and key database files created and modified with the `certutil` and `pk12util1` commands.
The newest supported version is 3.107. The NSS test database for this version was generated in a Fedora 41 container.
The oldest supported version is 3.51. The NSS test database for this version was generated in a Fedora 30 container.
(Support for 3.39 generated in a Fedora 28 container could be achieved by implementing PBE with SHA-1 and Triple DES-CBC, the default for encrypting private attributes with that version. Older versions of NSS use the legacy dbm database and do not work with this package.)

The leaf certificate imported into the NSS test database was generated with these commands:
```bash
step certificate create root-ca root-ca.crt root-ca.key --profile root-ca --no-password --insecure
step certificate create leaf leaf.crt leaf.key --ca ./root-ca.crt --ca-key ./root-ca.key --no-password --insecure
step certificate p12 leaf.p12 leaf.crt leaf.key --no-password --insecure
```
