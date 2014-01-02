#!/usr/bin/env python
"""
  ffpassdecrypt - Decode the passwords stored using Firefox browser. The script currently works only on Linux.

  Author : Pradeep Nayak (pradeep1288@gmail.com)
  usage: ./ffpassdecrypt.py [paths_to_location_of_files]

  Run it with no parameters to extract the standard passwords from all profiles of the current logged in user,
  or with an optional '-P' argument (before any path) to query the master password for decryption.

  Required files:
     + key3.db
     + signons.sqlite
     + cert8.db
  are used and needed to collect the passwords.

"""

from ctypes import (
	CDLL,
	Structure,
	c_int, c_uint, c_void_p, c_char_p, c_ubyte,
	cast, byref, string_at)
import struct
import sys
import os
import glob
import re
import time
import base64
import getopt
import getpass

# Password structures
class SECItem(Structure):
	_fields_ = [('type',c_uint),('data',c_void_p),('len',c_uint)]

class secuPWData(Structure):
	_fields_ = [('source',c_ubyte),('data',c_char_p)]

(SECWouldBlock, SECFailure, SECSuccess) = (-2,-1,0)
(PW_NONE, PW_FROMFILE, PW_PLAINTEXT, PW_EXTERNAL) = (0,1,2,3)


def findpath_userdirs():
	appdata = os.getenv('HOME')
	usersdir = appdata+os.sep+".mozilla"+os.sep+'firefox'
	userdir = os.listdir(usersdir)
	res=[]
	for user in userdir:
		if os.path.isdir(usersdir+os.sep+user):
			res.append(usersdir+os.sep+user)
	return res

def errorlog(row, path, libnss):
	print "----[-]Error while Decoding! writting error.log:"
	print libnss.PORT_GetError()
	try:
		f=open('error.log','a')
		f.write("-------------------\n")
		f.write("#ERROR in: %s at %s\n" %(path,time.ctime()))
		f.write("Site: %s\n"%row[1])
		f.write("Username: %s\n"%row[6])
		f.write("Password: %s\n"%row[7])
		f.write("-------------------\n")
		f.close()
	except IOError:
		print "Error while writing logfile - No log created!"



# reads the signons.sqlite which is a sqlite3 Database (>Firefox 3)
def readsignonDB(userpath, dbname, use_pass, libnss):
	if libnss.NSS_Init(userpath)!=0:
		print """Error Initalizing NSS_Init,\n
		propably no usefull results"""

	print "Dirname: %s"%os.path.split(userpath)[-1]

	keySlot = libnss.PK11_GetInternalKeySlot()
	libnss.PK11_CheckUserPassword(keySlot, getpass.getpass() if use_pass else "")
	libnss.PK11_Authenticate(keySlot, True, 0)

	uname = SECItem()
	passwd = SECItem()
	dectext = SECItem()

	pwdata = secuPWData()
	pwdata.source = PW_NONE
	pwdata.data = 0

	import sqlite3
	conn = sqlite3.connect(userpath+os.sep+dbname)
	c = conn.cursor()
	c.execute("SELECT * FROM moz_logins;")
	for row in c:
		print "--Site(%s):"%row[1]
		uname.data  = cast(c_char_p(base64.b64decode(row[6])),c_void_p)
		uname.len = len(base64.b64decode(row[6]))
		passwd.data = cast(c_char_p(base64.b64decode(row[7])),c_void_p)
		passwd.len=len(base64.b64decode(row[7]))
		if libnss.PK11SDR_Decrypt(byref(uname),byref(dectext),byref(pwdata))==-1:
			errorlog(row, userpath+os.sep+dbname, libnss)
		print "----Username %s" % string_at(dectext.data,dectext.len)
		if libnss.PK11SDR_Decrypt(byref(passwd),byref(dectext),byref(pwdata))==-1:
			errorlog(row, userpath+os.sep+dbname, libnss)
		print "----Password %s" % string_at(dectext.data,dectext.len)
	c.close()
	conn.close()
	libnss.NSS_Shutdown()


################# MAIN #################
def main():

	try:
		optlist, args = getopt.getopt(sys.argv[1:], 'P')
	except getopt.GetoptError as err:
		# print help information and exit:
		print str(err) # will print something like "option -a not recognized"
		usage()
		sys.exit(2)


	if len(args)==0:
		ordner = findpath_userdirs()
	else:
		ordner=args

	use_pass = False
	for o, a in optlist:
		if o == '-P':
			use_pass = True

	# Load the libnss3 linked file
	libnss = CDLL("libnss3.so")

	# Set function profiles

	libnss.PK11_GetInternalKeySlot.restype = c_void_p
	libnss.PK11_CheckUserPassword.argtypes = [c_void_p, c_char_p]
	libnss.PK11_Authenticate.argtypes = [c_void_p, c_int, c_void_p]

	for user in ordner:
		signonfiles = glob.glob(user+os.sep+"signons*.*")
		for signonfile in signonfiles:
			(filepath,filename) = os.path.split(signonfile)
			filetype = re.findall('\.(.*)',filename)[0]
			if filetype.lower() == "sqlite":
				readsignonDB(filepath, filename, use_pass, libnss)
			else:
				print "Unhandled Signons File: %s" % filename
				print "Skipping"

if __name__ == '__main__':
	main()
