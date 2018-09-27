#!/usr/bin/env python
import sys, requests, json, os
from bs4 import BeautifulSoup as bs

def enterRes(e):
	e = e.split('/', 1)[0]

	if e not in result:
		result.append(e)

def checkHackertarget():
	print('[!] Checking hackertarget.com')

	r = requests.get('https://api.hackertarget.com/hostsearch/?q=' + domain).text
	e = r.split('\n')

	print('\t - hackertarget processed')

	for i in e:
		enterRes(i.split(',')[0])

def checkPtrarchive():
	print('[!] Checking ptrarchive.com')

	c = requests.Session()
	h = {
		'Referer' : 'http://www.ptrarchive.com', 
		'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0',
		'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'Accept-Language' : 'en-US,en;q=0.5'
	}
	cookie = {'test' : 'test'}

	r = c.get('http://www.ptrarchive.com/tools/search3.htm?label=' + domain + '&date=ALL', headers = h, cookies = cookie).text
	s = bs(r, 'html.parser')
	e = s.find('pre').text.split('\n')

	print('\t - ptrarchive processed')

	for i in e:
		e = i[i.find(']'):].split(' ')
		
		try:
			if e[1].endswith('.' + domain) and not e[1].startswith('*'):
				enterRes(e[1])
		except IndexError:
			pass

def checkCertspotter():
	print('[!] Checking certspotter.com')

	r = requests.get('https://certspotter.com/api/v0/certs?domain=' + domain).text
	j = json.loads(r)

	print('\t - certspotter processed')

	for i in j:
		for e in i['dns_names']:
			if e.endswith('.' + domain) and not e.startswith('*'):
				enterRes(e)

def checkRiddler():
	print('[!] Checking riddler.io')

	r = requests.get('https://riddler.io/search?q=pld:' + domain).text
	s = bs(r, 'html.parser')
	e = s.findAll('td', class_ = 'col-lg-5 col-md-5 col-sm-5')

	print('\t - riddler processed')

	for i in e:
		enterRes(i.text.strip())

def checkCrt():
	print('[-] Checking crt.sh')

	r = requests.get('https://crt.sh/?q=%25' + domain).text
	s = bs(r, 'html.parser')
	e = s.findAll('table')[1].findAll('tr')

	print('\t - crt processed')

	for i in e:
		e = i.findAll('td')
		
		try:
			e = e[4].text

			if e.endswith('.' + domain) and not e.startswith('*'):
				enterRes(e)
		except IndexError:
			pass

def checkSecuritytrails():
	print('[!] Checking securitytrails.com')

	r = requests.get('https://securitytrails.com/list/apex_domain/' + domain).text
	s = bs(r, 'html.parser')
	e = s.findAll('td')

	print('\t - securitytrails processed')

	for i in e:
		e = i.find('a')

		if e:
			enterRes(e.text)

def checkThreatminer():
	print('[!] Checking threatminer.org')

	try:
		r = requests.get('https://api.threatminer.org/v2/domain.php?q=' + domain + '&rt=5', timeout = 6).text
		j = json.loads(r)

		print('\t - threatminer processed')

		for i in j['results']:
			enterRes(i)
	except requests.exceptions.Timeout:
		print('\t - threatminer down [Skipping]')
		pass 

def checkVirustotal():
	print('[!] Checking virustotal.com')

	r = requests.get('https://www.virustotal.com/ui/domains/' + domain + '/subdomains?limit=40').text
	j = json.loads(r)

	try:
		n = str(j['links']['next'])
		c = 1

		for i in j['data']:
			enterRes(i['id'])

		while type(n) is str:
			r = requests.get(n).text
			j = json.loads(r)

			for i in j['data']:
				enterRes(i['id'])

			try:
				n = str(j['links']['next'])
				c = c + 1
			except KeyError:
				break
	except KeyError:
		print('\t - Large Data')

		for i in j['data']:
			enterRes(i['id'])		

def checkThreatcrowd():
	print('[!] Checking threadcrowd.com')

	r = requests.get('https://threatcrowd.org/searchApi/v2/domain/report/?domain=' + domain).text
	j = json.loads(r)

	print('\t - threatcrowd processed')

	for e in j['subdomains']:
		enterRes(e)

def checkFindsubdomains():
	print('[!] Checking findsubdomains.com')

	r = requests.get('https://findsubdomains.com/subdomains-of/' + domain).text
	s = bs(r, 'html.parser')
	e = s.findAll('td', {'data-field' : 'Domain'})

	print('\t - findsubdomains processed')

	for i in e:
		enterRes(i['title'])

def checkDNSDumpster():
	print('[!] Checking dnsdumpster.com')

	print('\t - need token')

	c = requests.Session()
	r = c.get('https://dnsdumpster.com').text
	h = {'Referer' : 'https://dnsdumpster.com'}
	t = c.cookies.get_dict()['csrftoken']

	print('\t - got token: ' + t + ', proceeding')

	r = c.post('https://dnsdumpster.com', data = {'csrfmiddlewaretoken' : t, 'targetip' : domain}, headers = h).text
	s = bs(r, 'html.parser')
	t = s.findAll('table')[-1].findAll('td', class_ = 'col-md-4')
	print('\t - dnsdumpster processed')
	for i in t:
		t = i.text.split()[0]
		enterRes(t)


domain = sys.argv[1]
result = []
output = open(domain + '.txt', 'w')

print('Target set to: ' + domain)

functions = [

	checkDNSDumpster,
	checkFindsubdomains,
	checkThreatcrowd,
	checkThreatminer,
	checkVirustotal,
	checkSecuritytrails,
	checkHackertarget,
	checkCrt,
	checkCertspotter,
	checkRiddler,
	checkPtrarchive
]

for f in functions:
	f()

try:
	for i in result:
		output.write(i + '\n')
finally:
	output.close()

print('[!] Finished, printing result:')

os.system('cat ' + domain + '.txt')
print('[!] Counting ' + str(len(result)) + ' unique subdomains')
