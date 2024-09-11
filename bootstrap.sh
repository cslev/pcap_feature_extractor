#!/bin/bash
 
 ROOT="$(dirname "$0")"
 source $ROOT/sources/extra.sh
 
 
function show_help () 
 { 
 	c_print "White" "This script install necessary tools for the feature extraction. 
  \nIn particular, it install Zeek and tshark with all their requirements.  
  \nSupported OSes are Ubuntu and Debian (only)"
 	c_print "Bold" "Example: sudo ./bootstrap "
  c_print "Bold" "\t-d <DISTRO>: enforce distro here (e.g., ubuntu, debian) 
  (Default: read from /etc/os-release)."
  c_print "Bold" "\t-v <DISTRO_VER>: enforce distro version number (e.g., 22.04)
  Use in tandem with -d. (Default: read from /etc/os-release)"
 	exit $1
 }



DISTRO=""
DISTRO_VER=""

while getopts "h?d:v:" opt
 do
 	case "$opt" in
 	h|\?)
 		show_help
 		;;
  d)
 		DISTRO=$OPTARG
 		;;
  v)
  	DISTRO_VER=$OPTARG
 		;;  
 	*)
 		show_help
 		;;
 	esac
 done

if [[ -z $DISTRO && -z $DISTRO_VER ]]
then
  c_print "White" "Argument <DISTRO> not set, using OS default values..."
  # Check the Linux distribution
  if [ -f /etc/os-release ] 
  then
    . /etc/os-release
    DISTRO=$ID
    DISTRO_VER=$VERSION_ID
  else
    c_print "Red" "Error: Cannot determine the distribution. /etc/os-release file not found."
    c_print "Yellow" "You might enforce DISTRO with -d argument"
    exit 1
  fi
else
  c_print "Yellow" "DISTRO is enforced to be: ${DISTRO}"
  if [ -z $DISTRO_VER ]
  then
    c_print "Red" "No DISTRO_VER set! You have to specify that too"
    exit 4
  fi
fi


ZEEK_REPO_NAME=""
#install dependencies
if [[ "$DISTRO" == "ubuntu" ]] 
then
  c_print "Blue" "This is Ubuntu. Checking versions for Zeek..."
  if [[ "$DISTRO_VER" == "20.04" ]]
  then
    ZEEK_REPO_NAME="xUbuntu_20.04"
  elif [[ "$DISTRO_VER" == "22.04" ]]
  then
    ZEEK_REPO_NAME="xUbuntu_22.04"
  elif [[ "$DISTRO_VER" == "23.10" ]]
  then
    ZEEK_REPO_NAME="xUbuntu_23.10"
  elif [[ "$DISTRO_VER" == "24.04" ]]
  then
    ZEEK_REPO_NAME="xUbuntu_24.04"
  else
    c_print "Red" "Unsupported Ubuntu version ${DISTRO_VER}"
    exit 3
  fi  
elif [[ "$DISTRO" == "debian" ]]
then
  c_print "Blue" "This is Debian. Checking versions for Zeek..."
  if [[ "$DISTRO_VER" == "11" ]]
  then
    ZEEK_REPO_NAME="Debian_11"
  elif [[ "$DISTRO_VER" == "12" ]]
  then
    ZEEK_REPO_NAME="Debian_12"
  elif [[ "$DISTRO_VER" == "Testing" ]]
  then
    ZEEK_REPO_NAME="Debian_Testing"
  else
    c_print "Red" "Unsupported Debian version ${DISTRO_VER}"
    exit 3
  fi  

else
  c_print "Red" "Error: '${DISTRO}' is an unsupported distribution.  
  This script only supports Ubuntu and Debian."
  c_print "Yellow" "If you are sure what you are doing (e.g., you have an 
  ubuntu/debian flavoured OS), you can enforce it via '-d debian' or '-d ubuntu'"
  exit 2
fi

#this is only for getting credentials in the beginning for the rest of the scripts
sudo apt update

zeek_ver="6.0.6"
zeek_url="download.opensuse.org"
# installing zeek-6
c_print "Blue" "Downloading zeek-6.0"
mkdir -p zeek_debs/
printf \\r; printf "Downloading .deb files individually...(1/10)" 
wget -q -P zeek_debs/ https://${zeek_url}/repositories/security:/zeek/${ZEEK_REPO_NAME}/all/zeek-6.0-btest-data_${zeek_ver}-0_all.deb 
printf \\r; printf "Downloading .deb files individually...(2/10)" 
wget -q -P zeek_debs/ https://${zeek_url}/repositories/security:/zeek/${ZEEK_REPO_NAME}/all/zeek-6.0-btest_${zeek_ver}-0_all.deb
printf \\r; printf "Downloading .deb files individually...(3/10)" 
wget -q -P zeek_debs/ https://${zeek_url}/repositories/security:/zeek/${ZEEK_REPO_NAME}/all/zeek-6.0-client_${zeek_ver}-0_all.deb
printf \\r; printf "Downloading .deb files individually...(4/10)" 
wget -q -P zeek_debs/ https://${zeek_url}/repositories/security:/zeek/${ZEEK_REPO_NAME}/all/zeek-6.0-zkg_${zeek_ver}-0_all.deb
printf \\r; printf "Downloading .deb files individually...(5/10)" 
wget -q -P zeek_debs/ https://${zeek_url}/repositories/security:/zeek/${ZEEK_REPO_NAME}/amd64/zeek-6.0-core-dev_${zeek_ver}-0_amd64.deb 
printf \\r; printf "Downloading .deb files individually...(6/10)" 
wget -q -P zeek_debs/ https://${zeek_url}/repositories/security:/zeek/${ZEEK_REPO_NAME}/amd64/zeek-6.0-core_${zeek_ver}-0_amd64.deb 
printf \\r; printf "Downloading .deb files individually...(7/10)" 
wget -q -P zeek_debs/ https://${zeek_url}/repositories/security:/zeek/${ZEEK_REPO_NAME}/amd64/zeek-6.0-spicy-dev_${zeek_ver}-0_amd64.deb
printf \\r; printf  "Downloading .deb files individually...(8/10)" 
wget -q -P zeek_debs/ https://${zeek_url}/repositories/security:/zeek/${ZEEK_REPO_NAME}/amd64/zeek-6.0_${zeek_ver}-0_amd64.deb 
printf \\r; printf "Downloading .deb files individually...(9/10)" 
wget -q -P zeek_debs/ https://${zeek_url}/repositories/security:/zeek/${ZEEK_REPO_NAME}/amd64/zeekctl-6.0_${zeek_ver}-0_amd64.deb 
printf \\r; printf "Downloading .deb files individually...(10/10)" 
wget -q -P zeek_debs/ https://${zeek_url}/repositories/security:/zeek/${ZEEK_REPO_NAME}/amd64/libbroker-6.0-dev_${zeek_ver}-0_amd64.deb 
c_print "Bold" "\nInstalling downloaded Zeek debs..."
sudo dpkg -i zeek_debs/*.deb
sudo apt install -f

c_print "Bold" "Removing downloaded Zeek debs..."
rm -rf zeek_debs/

c_print "Bold" "Installing tshark..."
sudo apt install tshark

c_print "BGreen" "BOOTSTRAPPING DONE"





