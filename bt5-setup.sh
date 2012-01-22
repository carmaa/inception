#!/bin/bash

#----------------------------------------------------------------------------------------------------
# Setup script for BackTrackv5 by Glenn P. Edwards Jr.
# For use on other distros, some modifications to the script may be required.
# Other files referenced can be found at the following:
# FTWAutopwn : https://github.com/carmaa/FTWAutopwn
# libforensic1394 : https://freddie.witherden.org/tools/libforensic1394/
#----------------------------------------------------------------------------------------------------
IR_DIR="/pentest/forensics/IR"
FTWAutopwn_DIR="/pentest/forensics/IR/FTWAutopwn"
lib_version="libforensic1394-0.2"

echo -e "\n[+] Setting up the environment"
export LD_LIBRARY_PATH=/usr/local/lib

lsmod=$(lsmod | grep firewire_ohci 2>/dev/null)
if [ -z "$lsmod" ];then
	echo "[-] loading 'firewire-ohci' mod"
	sudo modprobe firewire-ohci
else
	echo "[-] 'firewire-ohci' mod already loaded - skipping"
fi


if [ -d $IR_DIR ]; then
	echo "[-] Directory '$IR_DIR' already exists - skipping"
else
	echo "[-] Creating directory '$IR_DIR'"
	mkdir $IR_DIR
fi


echo "[+] Downloading & installing required files"
cmake=$(dpkg -l | grep cmake 2>/dev/null)
if [ -z "$cmake" ]; then
	echo "[-] Installing 'cmake'"
	sudo apt-get install cmake	
else
	echo "[-] 'cmake' already installed - skipping" 
fi


python3=$(dpkg -l | grep python3 2>/dev/null)
if [ -z "$python3" ]; then
	echo "[-] Installing 'python3'"
	sudo apt-get install python3
else
	echo "[-] 'python3' already installed - skipping"
fi

	
if [ -f $IR_DIR/$lib_version.tar.gz ]; then
	echo "[-] '$lib_version.tar.gz' already downloaded - skipping"
else
	echo "[-] Downloading '$lib_version'"
	wget https://freddie.witherden.org/tools/libforensic1394/releases/$lib_version.tar.gz -P $IR_DIR
fi


echo "[+] Building '$lib_version' ..."	
cd $IR_DIR
tar xf $lib_version.tar.gz 
mkdir $IR_DIR/$lib_version/build &>/dev/null
cd $IR_DIR/$lib_version/build/
cmake -G"Unix Makefiles" ../ &>/dev/null
make &>/dev/null
sudo make install &>/dev/null
cd $IR_DIR/$lib_version/python/
sudo python3 setup.py install &>/dev/null


if [ -d $FTWAutopwn_DIR ]; then
FTWAutopwn=$(ls -l $FTWAutopwn_DIR/ 2>/dev/null)
	if [ -n "$FTWAutopwn" ]; then
		echo "[-] Directory 'FTWAutopwn' already exists - skipping"
	else
		echo "[-] Downloading 'FTWAutownpwn'"
		git clone https://github.com/carmaa/FTWAutopwn.git $FTWAutopwn_DIR
	fi

else 
	echo "[-] Downloading 'FTWAutopwn'"
	git clone https://github.com/carmaa/FTWAutopwn.git $FTWAutopwn_DIR
fi


echo "[+] Launching FTWAutopwn"
cd $FTWAutopwn_DIR/
python3 ftwautopwn.py