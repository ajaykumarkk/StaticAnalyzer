import subprocess
import iocextract
import re
from urlextract import URLExtract
import config
from src.file_check import *
import peutils,sys,os

path = "D:\\SRC\\staticanalyzer\\src\\u.exe"
USERDB = "D:\\SRC\\staticanalyzer\\src\\userdb.txt"

'''
with open(USERDB, 'rt') as f:
	sig_data = f.read()
signatures = peutils.SignatureDatabase(data=sig_data)
pe = pefile.PE(path)
matches = signatures.match_all(pe, ep_only = True)
print(matches)
'''


''' STRINGS
extractor = URLExtract()

out = subprocess.check_output(['strings64.exe','-a' ,'npp.7.6.Installer.exe'])
out = out.decode("utf-8").split('\n')
#print(str(out))
for url in iocextract.extract_urls(str(out)):
	print(extractor.find_urls(url))
'''
'''
#IMPORT FUNC CHECK
d=getsectionfunc("D:\\SRC\\staticanalyzer\\src\\u.exe")
for t in d.items():
	for fun in t[1]:
		try:
			print(t[0]+"-->"+fun+" : "+config.alerts[fun])
		except:
			pass
'''

'''#Entropy
with open(path, 'rb') as pe_file:
	pe_entropy = data_entropy(pe_file.read())
	
low_high_entropy = pe_entropy < 1 or pe_entropy > 7
if low_high_entropy:
	print("Possibly Packed")
	
p = peutils.is_probably_packed(pe)
print(p)
'''

'''
#section wise anlysis
section_data=section_analysis(path)
for i in section_data.keys():
	print(section_data[i])
'''
'''
#get packer details from section names
section_names = []
pe=pefile.PE(path)
for i in pe.sections:
	section_names.append(i.Name.strip(b"\x00").decode(errors='ignore').strip())
	try:
		print(config.packer_section_Details[i])
	except:
		pass

print(section_names)
'''
'''
good_sections = ['.data', '.text', '.code', '.reloc', '.idata', '.edata', '.rdata', '.bss', '.rsrc']
number_of_section = pe.FILE_HEADER.NumberOfSections
if number_of_section < 1 or number_of_section > 9:
	print("Suspicious No.of Sections{} ".format(number_of_section))
	suspicious_str=suspicious_str+"Suspicious No.of Sections{} ".format(number_of_section)
section_names=section_data.keys()
bad_sections = [bad for bad in section_names if bad not in good_sections]
print(bad_sections)
'''
'''
# Non-Ascii or empty section name check
section_names = getsectionnames(path)
for sec in section_names:
	if not re.match("^[.A-Za-z][a-zA-Z]+",sec):
		print("[*] Non-ascii or empty section names detected")

# Size of optional header check
pe=pefile.PE(path)
if pe.FILE_HEADER.SizeOfOptionalHeader != 224:
	print("[*] Illegal size of optional Header")

# Zero checksum check
if pe.OPTIONAL_HEADER.CheckSum == 0:
	print("[*] Header Checksum is zero!")

# Entry point check
enaddr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
vbsecaddr = pe.sections[0].VirtualAddress
ensecaddr = pe.sections[0].Misc_VirtualSize
entaddr = vbsecaddr + ensecaddr
if enaddr > entaddr:
	print("[*] Enrty point is outside the 1st(.code) section! Binary is possibly packed")

# Numeber of directories check
if pe.OPTIONAL_HEADER.NumberOfRvaAndSizes != 16:
	print("[*] Optional Header NumberOfRvaAndSizes field is valued illegal")

# Loader flags check
if pe.OPTIONAL_HEADER.LoaderFlags != 0:
	print("[*] Optional Header LoaderFlags field is valued illegal")
'''

