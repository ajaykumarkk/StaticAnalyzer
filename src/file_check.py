import subprocess
from subprocess import Popen
import pefile
import array
import math
import numbers
import time


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
	t = execute_command("sigcheck64.exe -e {} -nobanner ".format(path)).decode("utf-8")
	list = t.replace("\t", "").splitlines()
	if list[9].split("MachineType:") == '32-bit':
		return True
	return False


def check_dll(path):
	pass


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
	good_sectoins = ['.data', '.text', '.code', '.reloc', '.idata', '.edata', '.rdata', '.bss', '.rsrc']
	pe=pefile.PE(path)
	number_of_section = pe.FILE_HEADER.NumberOfSections
	if number_of_section < 1 or number_of_section > 9:
		print("Suspicious No.of Sections{} ".format(number_of_section))
	#print("{} {} {} {} {} {}".format("Section VirtualAddress VirtualSize SizeofRawData Sections_MD5_Hash Section_Entropy".split()))
	h_l_entropy = False
	suspicious_size_of_raw_data = False
	virtual_size = []
	section_names = []
	sections = {}
	for section in pe.sections:
		sec_name = section.Name.strip(b"\x00").decode(errors='ignore').strip()
		section_names.append(sec_name)
		entropy = section.get_entropy()
		for_section = False
		if entropy < 1 or entropy > 7:
			h_l_entropy = True
			for_section = True
		try:
			if section.Misc_VirtualSize / section.SizeOfRawData > 10:
				virtual_size.append((sec_name, section.Misc_VirtualSize))
		except:
			if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
				suspicious_size_of_raw_data = True
				virtual_size.append((section.Name.decode(errors='ignore').strip(), section.Misc_VirtualSize))
		section_info = {
		"Section": sec_name,
		"VirtualAddress": hex(section.VirtualAddress),
		"VirtualSize": section.Misc_VirtualSize,
		"SizeofRawData": section.SizeOfRawData,
		"Entropy": entropy
		}
		sections[sec_name] = section_info
	print(sections)