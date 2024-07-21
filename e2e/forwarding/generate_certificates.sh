../../nebula-cert ca -name "E2E test CA"
../../nebula-cert sign -name "A" -ip "192.168.100.1/24" -out-crt a.crt -out-key a.key
../../nebula-cert sign -name "B" -ip "192.168.100.2/24" -out-crt b.crt -out-key b.key
