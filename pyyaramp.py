#!/usr/bin/python

import sys, getopt
import operator
import os.path
import numpy
from multiprocessing import Process, Manager, freeze_support
import multiprocessing as mp
import itertools
import numpy as np
flat_list = [];
# Windows :1 Linux :0
osf = 1
list = ['rules/packer_compiler_signatures.yar','rules/antidebug_antivm.yar',"rules/crypto_signatures.yar","ruless/MALW_random.yar"]
regc = [b'IsConsole']

def initials():
	import platform
	global osf
	bet = platform.system()
	if bet == 'Windows':
		osf = 1
		freeze_support()
	if bet == 'Linux':
		osf = 0
		mtr()

def scanning(rulef,inputfile,return_dict):
	import yara
	fh = open(rulef, 'rb')
	#file_content = fh.read()
	#print (file_content)
	rule = yara.compile(file=fh)
	fh.close()
	#rules = yara.compile(filepath='D://all//scanner//yara//rules-master//index.yar')
	cache = str(rule.match(inputfile, timeout=60))
	print (cache)
	#cache2 = cache.split()
	#matches.append(cache)
	if cache:
		return_dict.extend(cache)
	else:
		return 0

def scanningmp(rulef,inputfile):
	import yara
	fh = open(rulef, 'rb')
	rule = yara.compile(file=fh)
	fh.close()
	cache = str(rule.match(inputfile, timeout=60))
	cache = cache.split()
	print (cache)
	if cache:
		return cache
	else:
		return 0
		
def adjust(inputfile):
	from pathlib import Path, PureWindowsPath
	inputfile = inputfile.replace('\\',"//")
	return inputfile
	#filename = PureWindowsPath(inputfile)
	#correct_path = Path(filename)
	#print (correct_path)

def listshorter(listinput):
	flat_list = []
	for sublist in listinput:
		for item in sublist:
			flat_list.append(item)
	return flat_list

def main(argv):
	from multiprocessing import Process, Manager, freeze_support
	import pymp
	procs = []
	jobs = []	
	inputfile = '';cachestr = []
	try:
		opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
	except getopt.GetoptError:
		print ("test.py -i "& inputfile)
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print ("test.py -i" & inputfile)
			sys.exit()
		elif opt in ("-i", "--ifile"):
			inputfile = arg
	inputfile = adjust(inputfile) 
	pymp.config.thread_limit = 1
	pymp.config.nested = True
	listo = pymp.shared.list()
	with pymp.Parallel(4) as p:
		for x in list:
			cache = (scanningmp(x,inputfile))
			if not (None in cache or '[]' in cache):
				listo.extend(cache)
	flat_list = str(listo)
	#matches = match.split()
	#flat_list = reduce(operator.concat, (flat_list))
	#matches = reduce(operator.concat, (matches))
	print (flat_list)
	return flat_list
	#print ('Input file is "', inputfile)

if __name__ == "__main__":
	initials()
	try:
		main(sys.argv[1:])
	except KeyboardInterrupt:
		try:
			try:
				#socket.disconnect(0);
				os.system("taskkill /f /im python.exe")
				sys.exit(0)
			except OSError:
				pass
		except SystemExit:
			os._exit(0)
