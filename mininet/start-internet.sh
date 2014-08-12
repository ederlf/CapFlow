while true; do
echo "HTTP/1.0 200 OK

<html>
<body>
<h1>This is the internet!</h1>
" | nc -l 80 || break;

done
