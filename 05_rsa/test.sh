#!/bin/bash
echo "[+] Generating RSA key pair..."
openssl genrsa -out priv.pem 1017
openssl rsa -in priv.pem -pubout -out pub.pem
echo "[+] Testing encryption..."
echo "hello" > plain.txt
./rsa.py encrypt pub.pem plain.txt enc.txt
openssl rsautl -decrypt -inkey priv.pem -in enc.txt -out dec.txt
diff -u plain.txt dec.txt
echo "[+] Testing decryption..."
openssl rsautl -encrypt -pubin -inkey pub.pem -in plain.txt -out enc.txt
./rsa.py decrypt priv.pem enc.txt dec.txt
diff -u plain.txt dec.txt
echo "[+] Testing signing..."
dd if=/dev/urandom of=filetosign bs=1M count=1
./rsa.py sign priv.pem plain.txt signature
openssl dgst -sha1 -verify pub.pem -signature signature plain.txt
echo "[+] Testing successful verification..."
openssl dgst -sha1 -sign priv.pem -out signature plain.txt
./rsa.py verify pub.pem signature plain.txt
echo "[+] Testing failed verification..."
openssl dgst -md5 -sign priv.pem -out signature plain.txt
./rsa.py verify pub.pem signature plain.txt