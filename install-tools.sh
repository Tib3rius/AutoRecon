#!/bin/bash

echo -e "\e[1;33m [+] Updating repositiories... \e[0m"
sudo apt -qq update &&
echo -e "\e[1;32m [+] Repositories updated! \e[0m"

echo -e "\e[1;33m [+] Installing tools from listing found in packages.txt... \e[0m"
while read package; do
	sudo apt -qq install $package -y
done < packages.txt
echo -e "\e[1;32m [+] All tools and dependencies installed! \e[0m"

echo -e "\e[1;33m [+] Cleaning system... \e[0m"
sudo apt -qq autoremove -y &&
sudo apt -qq autoclean &&
sudo apt -qq clean &&
echo -e "\e[1;32m [+] Done! \e[0m"
