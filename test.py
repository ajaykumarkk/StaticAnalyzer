import subprocess
import iocextract
import re
from urlextract import URLExtract
import config
from src.file_check import *
import peutils,sys,os
from urllib.parse import urlparse
from src.ip_reputaioncheck import *
import time

path = "D:\\SRC\\staticanalyzer\\samples\\a.exe"
USERDB = "D:\\SRC\\staticanalyzer\\src\\userdb.txt"

outfile =  "D:\\SRC\\staticanalyzer\\output\\a.txt"
out = open("D:\\SRC\\staticanalyzer\\output\\a.txt",'w')

out.write("------ Signature Check  --------")

out.write("Signature Exists : "+str(check_exe(path)))

out.write(check_descrip(path))

out.write("--------- PEID(signature Matching) ----------")
with open(USERDB, 'rt') as f:
	sig_data = f.read()
signatures = peutils.SignatureDatabase(data=sig_data)
pe = pefile.PE(path)
matches = signatures.match_all(pe, ep_only = True)
if matches is None:
	out.write("No Matches")
else:
	out.write(matches)

out.write("--------- strings  ----------")

#STRINGS
extract_url,ipv4,ipv6,emails = extractIOC(path)

out.write(extract_url)
out.write(ipv4)
out.write(ipv6)
out.write(emails)

out.write("--------- ipv4 reputaion check  ----------")

maldomainslist = getmaldomains()
out.write("Total Malware domains Loaded : "+str(len(maldomainslist)))
for i in extract_url:
	if urlparse(i).netloc in maldomainslist:
		out.write("Known Malicious Domain : "+i)

out.write(ipv4reputation_list(ipv4))

out.write("--------- Import function check  ----------")
#IMPORT FUNC CHECK
d=getsectionfunc(path)
for t in d.items():
	out.write(t[0]+"-->")
	for fun in t[1]:
		try:
			out.write("       "+fun+" : "+config.alerts[fun])
		except:
			pass

out.write("--------- Entropy  ----------")
#Entropy
with open(path, 'rb') as pe_file:
	pe_entropy = data_entropy(pe_file.read())
	
low_high_entropy = pe_entropy < 1 or pe_entropy > 7
if low_high_entropy:
	out.write("Possibly Packed")
	
p = peutils.is_probably_packed(pe)
if p is True:
	out.write("is packed : True")


out.write("--------- Section wise analysis  ----------")
#section wise anlysis
section_data=section_analysis(path)
for i in section_data.keys():
	out.write(section_data[i])


out.write("--------- get packer details from section names  ----------")

#get packer details from section names
section_names = []
pe=pefile.PE(path)

for i in pe.sections:
	section_names.append(i.Name.strip(b"\x00").decode(errors='ignore').strip())
	try:
		out.write(config.packer_section_Details[i])
	except:
		pass


out.write("--------- Uknown sections  ----------")

good_sections = ['.data', '.text', '.code', '.reloc', '.idata', '.edata', '.rdata', '.bss', '.rsrc']
number_of_section = pe.FILE_HEADER.NumberOfSections
if number_of_section < 1 or number_of_section > 9:
	out.write("Suspicious No.of Sections{} ".format(number_of_section))
section_names=section_data.keys()
bad_sections = [bad for bad in section_names if bad not in good_sections]
out.write("Unknown Sections : "+str(bad_sections))



# Non-Ascii or empty section name check
section_names = getsectionnames(path)
for sec in section_names:
	if not re.match("^[.A-Za-z][a-zA-Z]+",sec):
		out.write("[*] Non-ascii or empty section names detected")

# Size of optional header check
pe=pefile.PE(path)
if pe.FILE_HEADER.SizeOfOptionalHeader != 224:
	out.write("[*] Illegal size of optional Header")


# Zero checksum check
if pe.OPTIONAL_HEADER.CheckSum == 0:
	out.write("[*] Header Checksum is zero! - Non legitimate application")

# Entry point check
enaddr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
vbsecaddr = pe.sections[0].VirtualAddress
ensecaddr = pe.sections[0].Misc_VirtualSize
entaddr = vbsecaddr + ensecaddr
if enaddr > entaddr:
	out.write("[*] Enrty point is outside the 1st(.code) section! Binary is possibly packed")

# Numeber of directories check
if pe.OPTIONAL_HEADER.NumberOfRvaAndSizes != 16:
	out.write("[*] Optional Header NumberOfRvaAndSizes field is valued illegal")

# Loader flags check
if pe.OPTIONAL_HEADER.LoaderFlags != 0:
	out.write("[*] Optional Header LoaderFlags field is valued illegal")

#Point to symbol table
if pe.FILE_HEADER.PointerToSymbolTable > 0:
	out.write("[*] File contains some debug information, in majority of regular PE files, should not contain debug information")

#overlaydata check
overlayOffset = pe.get_overlay_data_start_offset()
raw = pe.write()
if overlayOffset != None:
	out.write("\nOverlay data is often associated with malware")
	out.write(' Start offset: 0x%08x' % overlayOffset)
	overlaySize = len(raw[overlayOffset:])
	raw= pe.write()
	out.write(' Size: 0x%08x %s %.2f%%' % (overlaySize, NumberOfBytesHumanRepresentation(overlaySize), float(overlaySize) / float(len(raw)) * 100.0))

out.write("\nMalicious flag check...")
#malicious flags check
if pe.FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_LO:
	out.write("Little endian: LSB precedes MSB in memory, deprecated and should be zero.")
if pe.FILE_HEADER.IMAGE_FILE_BYTES_REVERSED_HI:
	out.write("Big endian: MSB precedes LSB in memory, deprecated and should be zero.")
if pe.FILE_HEADER.IMAGE_FILE_RELOCS_STRIPPED:
	out.write("File does not contain base relocations and must therefore be loaded at its preferred base address.\nFlag has the effect of disabling Address Space Layout Randomization(ASLR) for the process.")


#out.write(pe.OPTIONAL_HEADER.SizeOfUninitializedData)
if pe.OPTIONAL_HEADER.SizeOfUninitializedData > 1:
	out.write("Possible malicious file has uninitialized data")

out.write("--------- Dll vulnerabilities check  ----------")
out.write(check_dll(path))

out.close()