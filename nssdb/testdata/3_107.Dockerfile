FROM fedora:41

RUN dnf install -y nss-tools sqlite

COPY fixtures.sh /bin
COPY leaf.p12 /

RUN mkdir /nssdb
WORKDIR /nssdb
