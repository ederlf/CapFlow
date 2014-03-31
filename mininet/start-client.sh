echo "Now getting a webpage, should redirect to captive portal"
echo
wget -O - 10.0.0.2
echo
echo
echo "Done"
echo "Now logging in"
echo
wget -O - 10.0.0.2/auth --post-data="username=test&password=test&redirect=10.0.0.2/"
echo
echo "Done"
echo "Now you should go to the internet"
echo
wget -O - 10.0.0.2

