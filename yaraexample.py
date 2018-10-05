#!/usr/bin/python

import sys, getopt
import operator
import os.path
import operator
inputfile = '';matches = [];flat_list = ''
list = ['rules/packer_compiler_signatures.yar','rules/antidebug_antivm.yar',"rules/crypto_signatures.yar","ruless/MALW_random.yar"]
data = dict()

def scanning(rulef):
	import yara
	global inputfile
	fh = open(rulef, 'rb')
	#file_content = fh.read()
	#print (file_content)
	rule = yara.compile(file=fh)
	fh.close()
	#rules = yara.compile(filepath='D://all//scanner//yara//rules-master//index.yar')
	cache = rule.match(inputfile, timeout=60)
	#cache2 = cache.split()
	matches.append(cache)
	if matches:
		return matches
	else:
		return 0
	
def adjust():
	from pathlib import Path, PureWindowsPath
	global inputfile
	inputfile = inputfile.replace('\\',"//")
	#filename = PureWindowsPath(inputfile)
	#correct_path = Path(filename)
	#print (correct_path)

def main(argv):
	global inputfile,matches
	inputfile = ''
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
			adjust() 
			for x in list:
				scanning(x)
			matches = reduce(operator.concat, matches)	
			print(matches)
			return matches
	#print ('Input file is "', inputfile)

if __name__ == "__main__":
	main(sys.argv[1:])
