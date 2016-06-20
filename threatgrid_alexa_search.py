#!/usr/bin/python
import socket
import re
import zipfile, io
import requests
from argparse import ArgumentParser
from pythreatgrid.threatgrid import domains
import json


def get_alexalist(top):
		''' Reads whitelist from top-1m.csv. If this fails, it fetches this list on Amazon.
		Args:
			None.
		Returns:
			domains - a dictionary of domains and rankings from whitelist.
		'''

		domains = {}
		count = 0
		
		try:	
			fp = open("top-1m.csv","r")
			lines = fp.readlines()
			for line in lines:
				if count < top:
					pair = line.rstrip().split(',')
					domains[pair[1]] = pair[0]
					count += 1
				else:
					break
		except:
			print("\n[!] Failed to open top-1m.csv...fetching from amazon...\n")
			r = requests.get("http://s3.amazonaws.com/alexa-static/top-1m.csv.zip",stream=True)
			z = zipfile.ZipFile(io.BytesIO(r.content))
			z.extractall()
			
			fp = open("top-1m.csv","r")
			lines = fp.readlines()
			for line in lines:
				if count < top:
					pair = line.rstrip().split(',')
					domains[pair[1]] = pair[0]
					count += 1
				else:
					break
		return domains


def get_tld(domain):
	''' Trims down a domain to it's top level 
	Args:
		Domain to trim.
	Returns:
		domain - A TLD representation of the passed domain.
	'''
	dot_indexes = [x for x,y in enumerate(domain) if y == '.']
	if len(dot_indexes) > 2:
		domain = domain[dot_indexes[1]+1:]
	elif len(dot_indexes) == 2:
		domain = domain[dot_indexes[0]+1:]
	
	return domain



def get_tg_domain_feed(options):
	''' Searches ThreatGrid for domains  and strips out related URLs found in the analysis.
	Args:
		checksum - hash value to search threatgrid for.
	Returns:
		urls - A set of URLs obtained from ThreatGrid Sample Analysis	.
	'''
	tg_iocs = list()
	for resp in domains(options):
		if 'data' in resp:
			for item in resp[u'data'][u'items']:
				tg_iocs.append(item)
	return tg_iocs


def filter_domains(tg_iocs,alexalist):
	''' Filters returned IOC's, removing any IOC that has a domain in the returned alexa list.
	Args:
		tg_iocs - list of json objects containing IOC information for today
		alexalist - dictionary of top alexa domains with their rank
	Returns:
		tg_iocs - returns a new filtered list of json objects, omitting anything with a domain matching alexa list
	'''
	for ioc in tg_iocs:
		domain = get_tld(ioc['domain'])

		if domain in alexalist.keys():
			print("[+] Match! : %s Ranked: %s" % (domain,alexalist[domain]))
			tg_iocs.remove(ioc)

	return tg_iocs

def write_iocs(tg_iocs):
	try:
		fp = open("filtered_ioc.csv","w")
		for ioc in tg_iocs:
			fp.write("%s\n" % ioc)
	except:
		print("[!] Failed to write filtered_ioc.csv\n")

def main():
	parser = ArgumentParser(description='Return threat intel from threagrid eliminating any domains that match alexa top 1m')
	parser.add_argument('api_key', type=str,
		help='API key for accessing Threatgrid')
	parser.add_argument('--top', type=str,
		help='Exclude results from top X domains in Alexa Top 1 Million Domains.')

	args = 	parser.parse_args()

	options = {
		'api_key' : args.api_key,
		'after' : 'yesterday'
	}
	try:
		top = int(args.top)
	except:
		top = 1000000

	tg_iocs = get_tg_domain_feed(options)
	before = len(tg_iocs)
	alexa = get_alexalist(top)
	tg_iocs = filter_domains(tg_iocs,alexa)
	after = len(tg_iocs)
	removed = before-after
	print("[+] Removed %s indicators" % removed)
	write_iocs(tg_iocs)

if __name__ == '__main__':
	main()

