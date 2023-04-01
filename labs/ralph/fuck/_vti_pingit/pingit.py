#!/usr/bin/python

import cgi
import os, commands

print "Content-type: text/html\n\n"
form=cgi.FieldStorage()
if (form.has_key("action")):
	output=os.popen("ping " + form["action"].value).readlines()
	for line in output:
		print line + "<br>" 
else:
	print "Please Enter Input!"
