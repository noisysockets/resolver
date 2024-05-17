# DNS over TLS Test Certificates

## Generate Certificates

```sh
cfssl genkey -initca ca-csr.json | cfssljson -bare ca
cfssl gencert -ca ca.pem -ca-key ca-key.pem server-csr.json | cfssljson -bare server
rm *.csr
```