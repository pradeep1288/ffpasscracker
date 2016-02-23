#!/usr/bin/env python
"""
  ffpassdecrypt - Decode the passwords stored using Firefox browser. The script currently works only on Linux.

  Author : Pradeep Nayak (pradeep1288@gmail.com)
  usage: ./ffpassdecrypt.py [paths_to_location_of_files]

  Run it with no parameters to extract the standard passwords from all profiles of the current logged in user,
  or with an optional '-P' argument (before any path) to query the master password for decryption.

  Required files:
     + key3.db
     + signons.sqlite / logins.json
     + cert8.db
  are used and needed to collect the passwords.

"""

from ctypes import (
	CDLL,
	Structure,
	c_int, c_uint, c_void_p, c_char_p, c_ubyte,
	cast, byref, string_at)
from ctypes.util import find_library
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
	usersdir = os.path.join(appdata, '.mozilla', 'firefox')
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
		f.write("Site: %s\n"%row['hostname'])
		f.write("Username: %s\n"%row['encryptedUsername'])
		f.write("Password: %s\n"%row['encryptedPassword'])
		f.write("-------------------\n")
		f.close()
	except IOError:
		print "Error while writing logfile - No log created!"


class JSONLogins(object):

	def __init__(self, dbpath):
		import json

		with open(dbpath) as fh:
			try:
				self._data = json.load(fh)
			except Exception as Error:
				raise RuntimeError("Failed to read %s (%s)" %
						   (Database, Error))

	def __iter__(self):
		return self._data['logins'].__iter__()

class SQLiteLogins(object):

	def __init__(self, dbpath):
		import sqlite3
		self._conn = sqlite3.connect(dbpath)
		self._cur = self._conn.cursor()
		self._cur.execute('SELECT * FROM moz_logins;')

	def __iter__(self):
		for row in self._cur:
			yield { 'hostname': row[1],
				'encryptedUsername': row[6],
				'encryptedPassword': row[7],
				'timeCreated' : row[10],
				'timeLastUsed' : row[11],
				'timePasswordChanged' : row[12]}

def decrypt(val, libnss, pwdata):
	try:
		item_bytes = base64.b64decode(val)
	except TypeError as msg:
		print "--TypeError (%s) val  (%s)"%(msg,val)
		return None

	item_sec = SECItem()
	item_clr = SECItem()

	item_sec.data = cast(c_char_p(item_bytes),c_void_p)
	item_sec.len = len(item_bytes)

	if libnss.PK11SDR_Decrypt(byref(item_sec), byref(item_clr), byref(pwdata))==-1:
		return None
	else:
		return string_at(item_clr.data, item_clr.len)


# reads the signons.sqlite which is a sqlite3 Database (>Firefox 3)
def readsignonDB(userpath, dbname, pw, libnss):
	print "\nDatabase %s" % dbname
        dbpath = os.path.join(userpath, dbname)

	keySlot = libnss.PK11_GetInternalKeySlot()
	libnss.PK11_CheckUserPassword(keySlot, pw)
	libnss.PK11_Authenticate(keySlot, True, 0)

	pwdata = secuPWData()
	pwdata.source = PW_NONE
	pwdata.data = 0

	ext = dbname.split('.')[-1]
	if ext == 'sqlite':
		db = SQLiteLogins(dbpath)
	elif ext == 'json':
		db = JSONLogins(dbpath)

	for rec in db:
		print "--Site(%s):" % rec['hostname']

		for item in ['Username', 'Password']:
			clr = decrypt(rec['encrypted%s' % item], libnss, pwdata)
			if clr is None:
				errorlog(rec, dbpath, libnss)
			else:
				print "----%s %s" % (item, clr)


		# Additional items from the JSON database

		for item in ['timeCreated', 'timeLastUsed', 'timePasswordChanged']:
			if item in rec:
				print "----%s %s" % (item, time.strftime("%Y-%m-%dT%H:%M:%S",time.localtime((rec[item]) / 1000)))


class LibNSS(object):
	def __init__(self, libnss, userpath):
		self._libnss = libnss
		if self._libnss.NSS_Init(userpath)!=0:
			raise RuntimeError("libnss init error")

	def __enter__(self):
		return self

	def __exit__(self, ExcType, ExcVal, ExcTb):
		self._libnss.NSS_Shutdown()

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
	libnss = CDLL(find_library("nss3"))

	# Set function profiles

	libnss.PK11_GetInternalKeySlot.restype = c_void_p
	libnss.PK11_CheckUserPassword.argtypes = [c_void_p, c_char_p]
	libnss.PK11_Authenticate.argtypes = [c_void_p, c_int, c_void_p]

	for user in ordner:
		print "Dirname: %s"%os.path.split(user)[-1]

		signonfiles = glob.glob(os.path.join(user, 'signons*.sqlite')) + \
			[os.path.join(user, 'logins.json')]

		pw = getpass.getpass() if use_pass else ""
		with LibNSS(libnss, user):
			for signonfile in signonfiles:
				(filepath,filename) = os.path.split(signonfile)
				readsignonDB(filepath, filename, pw, libnss)

if __name__ == '__main__':
	main()
