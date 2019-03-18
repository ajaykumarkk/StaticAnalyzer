import subprocess
from subprocess import Popen
import pefile
import array
import math
import numbers
import time
from urlextract import URLExtract
import iocextract
from urllib.parse import urlparse


def old_div(a, b):
	"""
	Equivalent to ``a / b`` on Python 2 without ``from __future__ import
	division``.
	"""
	if isinstance(a, numbers.Integral) and isinstance(b, numbers.Integral):
		return a // b
	else:
		return a / b


def execute_command(cmd):
	try:
		p1 = Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		output = p1.communicate()
		return output[0]
	except Exception as e:
		print(e)
		print('Exception in Executing Command')
		return []


def check_exe(path):
	execute_command("sigcheck64.exe -w res.txt -e " + path)
	f = open("res.txt", "r")
	if f.readlines()[1].find("Signed"):
		return True
	else:
		return False


def check_descrip(path):
	t = execute_command("sigcheck64.exe -e {} -nobanner ".format(path)).decode("utf-8")
	list = t.replace("\t", "").splitlines()
	print(len(list))
	desc = list[5].split("Description:")[1]
	if desc == 'n/a':
		print("The file has no desription")


def check32bit(path):
	t = execute_command("src\\sigcheck64.exe -e {} -nobanner ".format(path)).decode("utf-8")
	list = t.replace("\t", "").splitlines()
	if list[9].split("MachineType:")[1] == '32-bit':
		return True
	return False


def check_dll(path):
	print(check32bit(path))
	if check32bit(path):
		out = execute_command('src\\Siofra32.exe --mode file-scan -f "'+path+'" --enum-dependency --dll-hijack')
	else:
		print("64-Bit")
		out = execute_command('src\\Siofra64.exe --mode file-scan -f "'+path+'" --enum-dependency --dll-hijack')
	out=out.decode("utf-8").replace("\r\r","").split('\n')
	for i in out:
		print(i)


def getsectionfunc(path):
	file = pefile.PE(path)
	impdll = []
	impfuncdict = {}
	for item in file.DIRECTORY_ENTRY_IMPORT:
		impdll.append(item.dll.decode('utf-8'))
		temp_fun = []
		for impfuncs in item.imports:
			try:
				temp_fun.append((impfuncs.name).decode('utf-8'))
			except:
				pass
		impfuncdict[item.dll.decode('utf-8')] = temp_fun
	return impfuncdict


def data_entropy(data):
	"""Calculate the entropy of a chunk of data."""

	if len(data) == 0:
		return 0.0

	occurences = array.array('L', [0] * 256)

	for x in data:
		occurences[x if isinstance(x, int) else ord(x)] += 1

	entropy = 0
	for x in occurences:
		if x:
			p_x = old_div(float(x), len(data))
			entropy -= p_x * math.log(p_x, 2)

	return entropy


def check_date(path):
	pe=pefile.PE(path)
	val = pe.FILE_HEADER.TimeDateStamp
	pe_year = int(time.ctime(val).split()[-1])
	this_year = int(time.gmtime(time.time())[0])
	if pe_year > this_year or pe_year < 2000:
		return "[SUSPICIOUS COMPILATION DATE] - {}".format(pe_year)

def section_analysis(path):
	pe=pefile.PE(path)
	h_l_entropy = False
	suspicious_size_of_raw_data = False
	section_names = []
	sections = {}
	nsec = pe.FILE_HEADER.NumberOfSections
	for i in range(0,nsec):
		if i == nsec:
			break
		section = pe.sections[i]
		suspicious_str = ""
		virtual_size = []
		sec_name = section.Name.strip(b"\x00").decode(errors='ignore').strip()
		section_names.append(sec_name)
		if section.IMAGE_SCN_MEM_WRITE == True:
			suspicious_str= suspicious_str + "This section is Writable(suspicious) "
		if section.IMAGE_SCN_MEM_DISCARDABLE == True:
			suspicious_str= suspicious_str + "This section is Discardable(suspicious) "
		entropy = section.get_entropy()
		if entropy < 1 or entropy > 7:
			h_l_entropy = True
		try:
			if section.Misc_VirtualSize / section.SizeOfRawData > 10:
				virtual_size.append((sec_name, section.Misc_VirtualSize))
		except:
			if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
				suspicious_size_of_raw_data = True
				virtual_size.append((section.Name.decode(errors='ignore').strip(), section.Misc_VirtualSize))
		if virtual_size:
			for n, m in virtual_size:
				suspicious_str = suspicious_str + ' SUSPICIOUS size of the section "{}" when stored in memory - {}'.format(n,m)
		if h_l_entropy:
			suspicious_str = suspicious_str +" Very high or very low entropy means that file/section is compressed or encrypted since truly random data is not common."
		if suspicious_size_of_raw_data:
			suspicious_str = suspicious_str + " Suspicious size of the raw data raw data is Zero and Virtual Size is more than Zero"
		if i != nsec -1:
			nextp = pe.sections[i].SizeOfRawData + pe.sections[i].PointerToRawData
			currp = pe.sections[i + 1].PointerToRawData
			if nextp != currp:
				suspicious_str = suspicious_str + " The Size Of Raw data is valued illegal! Binary might crash your disassembler/debugger"
		section_info = {
		"Section": sec_name,
		"VirtualAddress": hex(section.VirtualAddress),
		"VirtualSize": section.Misc_VirtualSize,
		"SizeofRawData": section.SizeOfRawData,
		"Entropy": entropy,
		"msg": suspicious_str
		}
		sections[sec_name] = section_info
	return sections

def getsectionnames(path):
	pe = pefile.PE(path)
	section_names = []
	for i in pe.sections:
		section_names.append(i.Name.strip(b"\x00").decode(errors='ignore').strip())
	return section_names

def extractIOC(path):
	extractor = URLExtract()
	try:
		out=execute_command('src\\floss64.exe '+path)
	except:
		out=execute_command('src\\strings64.exe '+path)
	out = out.decode("utf-8").split('\n')
	extract_url = []
	ipv4 = []
	ipv6=[]
	emails=[]
	for url in iocextract.extract_urls(str(out), refang=True, strip=True):
		n = extractor.find_urls(url)
		try:
			n= n[0]
			n = str(n).replace("\\r", "")
			extract_url.append(n)
		except:
			pass
	extract_url = list(set(extract_url))
	for ip4 in iocextract.extract_ipv4s(str(out), refang=True):
		ipv4.append(ip4)
	for ip6 in iocextract.extract_ipv6s(str(out)):
		ipv6.append(ip6)
	for email in iocextract.extract_emails(str(out),refang=True):
		emails.append(str(email).replace("\\r", ""))
	return (extract_url,ipv4,ipv6,emails)

def getmaldomains():
	urlbl = open("D:\\SRC\\staticanalyzer\\src\\RW_URLBL.txt").read().strip().split("\n")
	dmbl = open("D:\\SRC\\staticanalyzer\\src\\RW_DOMBL.txt").read().strip().split("\n")
	domains=open("D:\\SRC\\staticanalyzer\\src\\justdomains.txt").read().strip().split("\n")
	list_of_mal_domains = []
	for n in dmbl:
		if n and not n.startswith("#"):
			list_of_mal_domains.append(n.strip())
	list_of_mal_urls = []
	for n in urlbl:
		if n and not n.startswith("#"):
			n = urlparse(n).netloc
			if n.startswith("www."):
				n = ".".join(n.split(".")[1:])
			list_of_mal_urls.append(n)
	#print(list_of_mal_domains)
	#print(list_of_mal_urls)
	return list(set(list_of_mal_domains+ list_of_mal_urls + domains))


def NumberOfBytesHumanRepresentation(value):
	if value <= 1024:
		return '%s bytes' % value
	elif value < 1024 * 1024:
		return '%.1f KB' % (float(value) / 1024.0)
	elif value < 1024 * 1024 * 1024:
		return '%.1f MB' % (float(value) / 1024.0 / 1024.0)
	else:
		return '%.1f GB' % (float(value) / 1024.0 / 1024.0 / 1024.0)
