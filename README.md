# go-jwt

## Description

jwt tools

## generate key

```shell
openssl genpkey -algorithm RSA -out jwt_privkey.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in jwt_privkey.pem -out jwt_pubkey.pem
```
