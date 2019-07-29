#!/bin/bash

curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
#if the below lines don't work correctly, try using 'pip' instead of 'pip3'

pip3 install requests
pip3 install tabulate
pip3 install urllib3
pip3 install configparser
if [[ "$OSTYPE" == "linux-gnu" ]]; then
        xdg-open "https://github.com/bobthebutcher/viptela"
        xdg-open "https://www.python.org/download/releases/3.0/"
elif [[ "$OSTYPE" == "darwin"* ]]; then
        open "https://github.com/bobthebutcher/viptela"
        open "https://www.python.org/download/releases/3.0/"
elif [[ "$OSTYPE" == "msys" ]]; then
		start "https://github.com/bobthebutcher/viptela"
		start "https://www.python.org/download/releases/3.0/"
else
        echo "If browser doesn't open up with a github repo, go to https://github.com/bobthebutcher/viptela"
fi
echo "if there is an error with installing the packages, try pip not pip3"
sleep 10

echo "Make sure you download the zip file off the github page and then put the file in the same folder as the Exelon_vManage.py"
echo "You may need to delete the folder containing all the Viptela files so the Python script can find the files correctly"

read -p "Press any character and hit enter to exit"