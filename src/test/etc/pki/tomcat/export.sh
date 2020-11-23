openssl pkcs12 -in localhost.pfx -nocerts -nodes -out localhost.key
openssl pkcs12 -in localhost.pfx -clcerts -nokeys -out localhost.crt
# https://unix.stackexchange.com/a/393484