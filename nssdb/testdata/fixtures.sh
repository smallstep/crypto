#!/bin/bash

set -euxo pipefail

function main() {
	cd /nssdb
	# Create a new database. This will generate key4.db, cert9.db and pkcs11.txt files.
	certutil -N -d . --empty-password

	# Import our leaf certificate and private key into the NSS database. This will
	# add one record to the nssPrivate table in the key4.db for the private key and
	# two records to the nssPublic table in the cert9.db - one for the certificate
	# and one for its public key. This will also add a record to the metaData table
	# in the key4.db that holds a signature of the private key's value.
	pk12util -i /leaf.p12 -d . -W ''

	# column a0 holds the CKA_CLASS attribute
	certID=$(sqlite3 cert9.db "select id from nssPublic where a0 = X'00000001'")
	pubKeyID=$(sqlite3 cert9.db "select id from nssPublic where a0 = X'00000002'")
	privateKeyID=$(sqlite3 key4.db "select id from nssPrivate where a0 = X'00000003'")

	echo "certificate ${certID}" >> ids.txt
	echo "public-key ${pubKeyID}" >> ids.txt
	echo "private-key ${privateKeyID}" >> ids.txt
}

main "$@"
