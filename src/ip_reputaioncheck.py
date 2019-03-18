import requests
import re
import os,sys
import unicodedata
import string


cookies = {
    'cookiebanner-accepted': '1',
    'optinmodal': 'shown',
    '__utmt': '1',
    '__utma': '67803593.580391096.1496747284.1497281718.1497345596.7',
    '__utmb': '67803593.1.10.1497345596',
    '__utmc': '67803593',
    '__utmz': '67803593.1496747284.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none)',
}


headers = {
    'Origin': 'http://www.ipvoid.com',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.8',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Cache-Control': 'max-age=0',
    'Referer': 'http://www.ipvoid.com/',
    'Connection': 'keep-alive',
}

def ipv4reputation_live(ip):
    data = [('ip', ip),]
    g = requests.post('http://www.ipvoid.com/ip-blacklist-check/', headers=headers, cookies=cookies, data=data)
    string1 = str(unicodedata.normalize('NFKD', g.text).encode('ascii', 'ignore'))
    r = string1.replace("\n","").replace("\t","").replace("\r","")
    #print(str(ip) + str(re.findall(r'BLACKLISTED \d+\/\d+', str(r))))
    m = re.search(r'BLACKLISTED (\d+\/\d+)', str(r))
    if m:
        score = m.group(1)
        return score
    else:
        return 0

def ipv4reputation_list(ip_list):
    ipbl=open("D:\\SRC\\staticanalyzer\\src\\ipbl.txt").read().split("\n")
    print("Total IP blacklist loaded : "+str(len(ipbl)))
    malicious_ips=[]
    for i in ip_list:
        if i in ipbl:
            malicious_ips.append(i)
    return malicious_ips
