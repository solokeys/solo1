#
#
[[ "$#" != 4 ]] && echo "usage: $0 <private-key> <CA-cert> <signing-key> <output-cert>" && exit 1

# generate a "signing request"
echo "generate request"
openssl req -new -key "$1" -out "$1".csr

# CA sign the request
echo "sign request with CA key"
openssl x509 -days 18250 -req -in "$1".csr -extfile v3.ext -CA "$2" -CAkey "$3" -out "$4" -set_serial 0

echo "output as der"
openssl  x509 -in "$4" -outform der -out "$4".der
