#!/bin/bash

# Directories
cur=`pwd`
tmp=`mktemp -d`
scriptName=`basename $0`

# Certificate Variables
OUTPATH="./"
VERBOSE=0
DURATION=3650 # 10 years

safeExit() {
  if [ -d $tmp ]; then
    if [ $VERBOSE -eq 1 ]; then
      echo "Removing temporary directory '${tmp}'"
    fi
    rm -rf $tmp
  fi

  trap - INT TERM EXIT
  exit
}

# Help Screen
help() {
  echo -n "${scriptName} [OPTIONS] -c=US --state=California

Generate self-signed TLS certificate using OpenSSL

 Options:
  -c|--country         Country Name (2 letter code)
  -s|--state           State or Province Name (full name)
  -l|--locality        Locality Name (eg, city)
  -o|--organization    Organization Name (eg, company)
  -u|--unit            Organizational Unit Name (eg, section)
  -n|--common-name     Common Name (e.g. server FQDN or YOUR name)
  -e|--email           Email Address
  -p|--path            Path to output generated keys
  -d|--duration        Validity duration of the certificate (in days)
  -h|--help            Display this help and exit
  -v|--verbose         Verbose output
"
}

# Test output path is valid
testPath() {
  if [ ! -d $OUTPATH ]; then
    echo "The specified directory \"${OUTPATH}\" does not exist"
    exit 1
  fi
}

# Process Arguments
while [ "$1" != "" ]; do
  PARAM=`echo $1 | awk -F= '{print $1}'`
  VALUE=`echo $1 | awk -F= '{print $2}'`
  case $PARAM in
    -h|--help) help; safeExit ;;
    -c|--country) C=$VALUE ;;
    -s|--state) ST=$VALUE ;;
    -l|--locality) L=$VALUE ;;
    -o|--organization) O=$VALUE ;;
    -u|--unit) OU=$VALUE ;;
    -n|--common-name) CN=$VALUE ;;
    -e|--email) emailAddress=$VALUE ;;
    -p|--path) OUTPATH=$VALUE; testPath ;;
	-d|--duration) DURATION=$VALUE ;;
    -v|--verbose) VERBOSE=1 ;;
    *) echo "ERROR: unknown parameter \"$PARAM\""; help; exit 1 ;;
  esac
  shift
done

# Prompt for variables that were not provided in arguments
checkVariables() {
  # Country
  if [ -z $C ]; then
    echo -n "Country Name (2 letter code) [AU]:"
    read C
  fi

  # State
  if [ -z $ST ]; then
    echo -n "State or Province Name (full name) [Some-State]:"
    read ST
  fi

  # Locality
  if [ -z $L ]; then
    echo -n "Locality Name (eg, city) []:"
    read L
  fi

  # Organization
  if [ -z $O ]; then
    echo -n "Organization Name (eg, company) [Internet Widgits Pty Ltd]:"
    read O
  fi

  # Organizational Unit
  if [ -z $OU ]; then
    echo -n "Organizational Unit Name (eg, section) []:"
    read OU
  fi

  # Common Name
  if [ -z $CN ]; then
    echo -n "Common Name (e.g. server FQDN or YOUR name) []:"
    read CN
  fi

  # Common Name
  if [ -z $emailAddress ]; then
    echo -n "Email Address []:"
    read emailAddress
  fi
}

# Show variable values
showVals() {
  echo "Country: ${C}";
  echo "State: ${ST}";
  echo "Locality: ${L}";
  echo "Organization: ${O}";
  echo "Organization Unit: ${OU}";
  echo "Common Name: ${CN}";
  echo "Email: ${emailAddress}";
  echo "Output Path: ${OUTPATH}";
  echo "Certificate Duration (Days): ${DURATION}";
  echo "Verbose: ${VERBOSE}";
}

# Init
init() {
  cd $tmp
  pwd
}

# Cleanup
cleanup() {
  echo "Cleaning up"
  cd $cur
  rm -rf $tmp
}

buildCsrCnf() {
cat << EOF > ${tmp}/tmp.csr.cnf
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C=${C}
ST=${ST}
L=${L}
O=${O}
OU=${OU}
CN=${CN}
emailAddress=${emailAddress}
EOF
}

buildExtCnf() {
cat << EOF > ${tmp}/v3.ext
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${CN}
EOF
}

# Build TLS Certificate
build() {
  # Santizie domain name for file name
  FILENAME=${CN/\*\./}
  # Generate CA key & crt
  openssl genrsa -out ${tmp}/tmp.key 2048
  openssl req -x509 -new -nodes -key ${tmp}/tmp.key -sha256 -days ${DURATION} -out ${OUTPATH}${FILENAME}_CA.pem -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${CN}/emailAddress=${emailAddress}"

  # CSR Configuration
  buildCsrCnf

  # Create v3.ext configuration file
  buildExtCnf

  # Server key
  openssl req -new -sha256 -nodes -out ${OUTPATH}${FILENAME}.csr -newkey rsa:2048 -keyout ${OUTPATH}${FILENAME}.key -config <( cat ${tmp}/tmp.csr.cnf )

  # Server certificate
  openssl x509 -req -in ${OUTPATH}${FILENAME}.csr -CA ${OUTPATH}${FILENAME}_CA.pem -CAkey ${tmp}/tmp.key -CAcreateserial -out ${OUTPATH}${FILENAME}.crt -days ${DURATION} -sha256 -extfile ${tmp}/v3.ext
}

checkVariables
build
# showVals
safeExit
