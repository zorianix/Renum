#!/usr/bin/env python

import urllib3, requests, json
import argparse
import socket
from bs4 import BeautifulSoup

parser = argparse.ArgumentParser()
parser.add_argument('domain', help = 'domain (by URL;e.g. https://test.com)', type = str)

args = parser.parse_args()

whatcms_token = '1107cde730310755bcab5768e181de50ecaa2fcd3986e5dc66334f2ced4af4d2f9d97b'
domain = args.domain


def throwOptions():
	http = urllib3.PoolManager()
	request = http.request('OPTIONS', domain, retries=False, redirect=False)

	try:
		allow = str(r.headers['Allow'])
		if allow:
			print('[-] Allowed HTTP-methods: ' + allow)
		else:
			print('[!] HTTP-OPTIONS failed')
	except:
		print('[!] HTTP-OPTIONS failed')
		pass

def throwHeaders():
	headers = requests.get(domain).headers
	server = ''

	print('[-] HTTP-response header:\n---')
	for key,value in headers.items():
		print('\t' + key + ': ' + value)

		if key == 'Server':
			server = value

	if server:
		print('---\n[-] Webserver detected: ' + server)
	else:
		print('---\n[!] No "Server"-header')

def getCMS():
	request = requests.get('https://whatcms.org/APIEndpoint/Detect?url=' + domain + '&key=' + whatcms_token)
	response = json.loads(request.text)

	status = response['result']['code']

	if 'retry_in_seconds' in response:
		print('[-] CMS-API overload, try again i: ' + str(response['retry_in_seconds']) + 's')
	else:
		if status == 200:
			print('[-] CMS detected: ' + response['result']['name'])
		else:
			print('[!] No CMS detected')

def getTechnology():
	html = requests.get('http://w3techs.com/siteinfo.html?fx=y&url=' + domain).text
	soup = BeautifulSoup(html, 'lxml')
	try:
		table = soup.findAll('table', attrs={'class':'w3t_t'})[0]
		trs = table.findAll('tr')

		print('[-] W3-technologies:\n--')

		for tr in trs:
			th = tr.find('th')
			td = tr.find('td').text
			
			if td[-7:] == 'more...':
				td = td[:-9]
			
			print('\t' + th.text + ': ' + td)

		print('--')
	except:
		print('[!] Technology Enumeration failed')
		pass

def throwRobots():
	request = requests.get(domain + '/robots.txt')
	
	if(request.status_code == 200):
		print('[-] Fetched robots.txt:\n--')
		lines = filter(None, request.text.split('\n'))
		
		for line in lines:
			print('\t' + line)
		
		print('--')
	else:
		print('[!] No robots.txt')

def getInteresting():


	files = ['.idea/WebServers.xml', 'config/databases.yml', '.git/config', '.svn/entries', 'server-status', 'filezilla.xml', 'sitemanager.xml','.DS_Store', '_FILE_.bak', 'dump.sql', 'database.sql', 'backup.sql','.htaccess','web.config','README','crossdomain.xml','phpinfo.php','access.log','README.txt','INSTALL','INSTALL.txt','CHANGELOG.txt','.svn/','phpmyadmin/','bo','data.sql', 'db_backup.sql', 'db.sql', 'localhost.sql', 'mysql.sql', 'site.sql','server-status''temp.sql', 'users.sql', 'app/etc/local.xml', 'server.key', 'key.pem', 'id_rsa', 'id_dsa','.php_cs.cache','.env', '.ssh/id_rsa', '.ssh/id_dsa', 'cgi-bin/cgiecho', 'cgi-sys/cgiecho', 'winscp.ini', 'sites/default/private/files/backup_migrate/scheduled/test.txt','lb.txt',]

	print('[!] Checking interesting files')

	for count, file in enumerate(files):
		req = requests.get(domain + '/' + file)
		if req.status_code == 200:
			print('[-] Found interesting file: /' + file+'\r\n-----')
			print(req.text+'\r\n----')

recon = [
	throwOptions,
#	throwTrace,
	throwHeaders,
	getTechnology,
	getCMS,
	throwRobots,
	getInteresting
]

for module in recon:
	module()

print('[!]RENUM Completed: ' + domain)
