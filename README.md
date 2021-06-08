# go-jwt

## Description

jwt tools

## generate key

```shell
ssh-keygen -t rsa -b 4096 -m PEM -f priv.key
openssl rsa -in priv.key -pubout -outform PEM -out pub.key
```
