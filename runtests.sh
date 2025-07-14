#!/bin/bash -f

usage() {
  echo "Usage: "
  echo "$0 [-d] [-D] [-c] [-i][-t <test class name without the package prefix com.salesforce.dataloader e.g. dyna.DateConverterTest>] [--pkceport PORT] [--clientid CLIENT_ID] [--chromedriver PATH] [--geckodriver PATH] <test org URL> <test admin username> <test regular user username> <encrypted test password>"
  echo "Listening on port 5005 for IDE to start the debugging session if -d is specified."
  echo "Run 'mvn clean package' before encrypting password if -c is specified."
  echo "Ignore test failures and continue test run if -i is specified."
  exit 1
}

# Default values for named arguments
PKCEPORT=7171
CLIENTID="YOUR_CLIENT_ID"
CHROMEDRIVER="/usr/local/bin/chromedriver"
GECKODRIVER="/usr/local/bin/geckodriver"
CLIENTID_PKCE=""
CLIENTID_SERVER=""
CLIENTID_DEVICE=""

# Parse named arguments before getopts
while [[ $# -gt 0 ]]; do
  case $1 in
    --pkceport)
      PKCEPORT="$2"
      shift 2
      ;;
    --clientid)
      CLIENTID="$2"
      shift 2
      ;;
    --clientid-pkce)
      CLIENTID_PKCE="$2"
      shift 2
      ;;
    --clientid-server)
      CLIENTID_SERVER="$2"
      shift 2
      ;;
    --clientid-device)
      CLIENTID_DEVICE="$2"
      shift 2
      ;;
    --chromedriver)
      CHROMEDRIVER="$2"
      shift 2
      ;;
    --geckodriver)
      GECKODRIVER="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*|--*)
      break
      ;;
    *)
      break
      ;;
  esac
done

# To generate encrypted password
# build jar with the following command:
# mvn clean package -DskipTests
# run the following command to get encrypted password for the test admin account:
#java -cp target/dataloader-*.jar com.salesforce.dataloader.security.EncryptionUtil -e <password>

test=""
debug=""
debugEncryption=""
#encryptionFile=${HOME}/.dataloader/dataLoader.key
encryptionFileFlag=""

failfast="-Dsurefire.skipAfterFailureCount=5"

while getopts ":dDicv:t:f:" flag
do
  case "${flag}" in
    d)
      debug="-Dmaven.surefire.debug=-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=0.0.0.0:5005"
      ;;
    D)
      debugEncryption="-Xdebug -Xrunjdwp:server=y,transport=dt_socket,address=0.0.0.0:5005,suspend=y"   
      ;;
    t)
      test="-Dskip-unit-tests=true -Dtest=com.salesforce.dataloader.${OPTARG}"
      ;;
    f)
      encryptionFileFlag="-Dtest.encryptionFile=${OPTARG}"
      ;;
    i)
      failfast=""
      ;;
    *)
      usage
      ;;
  esac
done
shift $((OPTIND -1))

# $1 contains the test org URL
# $2 test admin user username
# $3 test regular user username
# $4 test admin and regular user encoded password

if [ "$#" -lt 4 ]; then
  usage
fi 

#echo $@

mvn clean package -Dmaven.test.skip=true
jarname="$(find ./target -name 'dataloader-[0-9][0-9].[0-9].[0-9].jar' | tail -1)"

#echo "password = ${4}"
encryptedPassword="$(java ${debugEncryption} -cp ${jarname} com.salesforce.dataloader.process.DataLoaderRunner run.mode=encrypt -e ${4} ${encryptionFile} | tail -1)"

additionalOptions=""
for option in $@
do
    if [[ ${option} == -D* ]]; then
        additionalOptions+=" "
        additionalOptions+=${option}
    fi
done

# uncomment the following lines to debug issues with password encryption
#echo "encryptedPassword = ${encryptedPassword}"
#decryptedPassword="$(java ${debugEncryption} -cp ${jarname} com.salesforce.dataloader.process.DataLoaderRunner run.mode=encrypt -d ${encryptedPassword} ${encryptionFile} | tail -1)"
#echo "decryptedPassword = ${decryptedPassword}"

# Build extra clientid options for Maven
CLIENTID_PKCE_OPT=""
CLIENTID_SERVER_OPT=""
CLIENTID_DEVICE_OPT=""
if [ -n "$CLIENTID_PKCE" ]; then
  CLIENTID_PKCE_OPT="-Dtest.clientid.pkce=$CLIENTID_PKCE"
fi
if [ -n "$CLIENTID_SERVER" ]; then
  CLIENTID_SERVER_OPT="-Dtest.clientid.server=$CLIENTID_SERVER"
fi
if [ -n "$CLIENTID_DEVICE" ]; then
  CLIENTID_DEVICE_OPT="-Dtest.clientid.device=$CLIENTID_DEVICE"
fi

mvn ${failfast} -Dtest.endpoint=${1} -Dtest.user.default=${2} -Dtest.user.restricted=${3} -Dtest.password=${encryptedPassword} ${encryptionFileFlag} -Dtest.pkceport=${PKCEPORT} -Dtest.clientid=${CLIENTID} $CLIENTID_PKCE_OPT $CLIENTID_SERVER_OPT $CLIENTID_DEVICE_OPT -Dwebdriver.chrome.driver=${CHROMEDRIVER} -Dwebdriver.gecko.driver=${GECKODRIVER} verify ${debug} ${test} ${additionalOptions}
