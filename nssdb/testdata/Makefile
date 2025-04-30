v3.107:
	mkdir v3.107
	docker build -t nssdb-v3.107 -f 3_107.Dockerfile .
	docker run --rm -it --volume ./v3.107:/nssdb nssdb-v3.107 /bin/fixtures.sh

v3.51:
	mkdir v3.51
	docker build -t nssdb-v3.51 -f 3_51.Dockerfile .
	docker run --rm -it --volume ./v3.51:/nssdb nssdb-v3.51 /bin/fixtures.sh
