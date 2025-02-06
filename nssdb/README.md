This package is for inserting a certificate and key into an NSS database.

## NSS Database Internals

Certificates, public keys, and private keys are stored as PKCS #11 objects.
Each object is a collection of attributes stored in binary format.
Some attributes are ASN.1 encoded.
Refer to the PKCS #11 spec for documentation on how an attribute is encoded.

### Schema

An NSS DB directory will include a file `certs9.db` that holds the certificate database and a file `key4.db` that holds the keys database.
Both are sqlite databases.
The certificates database comprises a single table `nssPublic`.
The keys database comprises a table named `metaData` and a table named `nssPrivate`.
The `nssPublic` and `nssPrivate` tables have the same schema.
As of NSS 3.107 there are 119 columns in these tables.
Each column holds the value of an attribute on the PKCS #11 object.

### Encryption and signing

The CKA_VALUE of private key objects in the key4 database is encrypted and encoded.
The encoded structure includes parameters necessary to decrypt the value.
This package uses the same defaults as NSS 3.107:

* Generate keys with PBKDF2 with a unique salt and target length 32
* PBKDF2 uses 1 iteration with an empty password and 10000 when the password is set
* Encrypt with AES256-CBC with a unique initialization vector
* Sign with HMAC-SHA256

A signature of the private key is stored in the metaData table since AES256-CBC encryption is not authenticated.
The signature is over the 32-byte raw private key along with object ID and attribute type.

## Generating Column Names

The `generate` directory holds a utility for generating a map from attribute names in the nss source code to column names in the sqlite databases.
The sqlite column name is always the letter `a` followed by a number in hexadecimal format.
For example, the `CKA_ISSUER` attribute has the column name `a81` in the `nssPublic` and `nssPrivate` tables of the sqlite database.
This is parsed from the following line in `lib/util/pkcs11t.h`.
```
#define CKA_ISSUER 0x00000081UL
```

To update the column map, clone the nss repo into the generate directory and then run `make columns`.

## Status

This package only supports importing certificates with an EC P-256 keypair.
