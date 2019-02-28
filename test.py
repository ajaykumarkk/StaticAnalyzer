import subprocess
import iocextract
import re
from urlextract import URLExtract
import config
from src.file_check import *


path = "D:\\SRC\\staticanalyzer\\src\\VegaSetup64.exe"

''' STRINGS
extractor = URLExtract()

out = subprocess.check_output(['strings64.exe','-a' ,'npp.7.6.Installer.exe'])
out = out.decode("utf-8").split('\n')
#print(str(out))
for url in iocextract.extract_urls(str(out)):
	print(extractor.find_urls(url))
'''

'''IMPORT FUNC CHECK
d=getsections("D:\\SRC\\staticanalyzer\\src\\VegaSetup64.exe")
for t in d.items():
	for fun in t[1]:
		try:
			print(t[0]+"-->"+fun+" : "+config.alerts[fun])
		except:
			pass
'''
'''Entropy
with open(path, 'rb') as pe_file:
	pe_entropy = data_entropy(pe_file.read())
	
low_high_entropy = pe_entropy < 1 or pe_entropy > 7
if low_high_entropy:
	print("Possibly Packed")
'''

section_data=section_analysis(path)
print(section_data['.data'])

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