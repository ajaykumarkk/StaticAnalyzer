import subprocess
import iocextract
import re
from urlextract import URLExtract
import config
from src.file_check import *


path = "D:\\SRC\\staticanalyzer\\src\\VegaSetup64.exe"

'''
extractor = URLExtract()

out = subprocess.check_output(['strings64.exe','-a' ,'npp.7.6.Installer.exe'])
out = out.decode("utf-8").split('\n')
#print(str(out))
for url in iocextract.extract_urls(str(out)):
	print(extractor.find_urls(url))
'''

'''
d=getsections("D:\\SRC\\staticanalyzer\\src\\VegaSetup64.exe")
for t in d.items():
	for fun in t[1]:
		try:
			print(t[0]+"-->"+fun+" : "+config.alerts[fun])
		except:
			pass
'''
'''
with open(path, 'rb') as pe_file:
	pe_entropy = data_entropy(pe_file.read())
	
low_high_entropy = pe_entropy < 1 or pe_entropy > 7
if low_high_entropy:
	print("Possibly Packed")
'''

print(section_analysis(path))