#!/usr/bin/python2
#
#  hostmap.py
#
#  Copyright 2017 Corey Gilks <CoreyGilks [at] gmail [dot] com>
#  Twitter: @CoreyGilks
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#
# This script was inspired by this article:
# https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/
from __future__ import print_function

import argparse
import logging
import os
import re
import socket
import sys
from threading import Thread, BoundedSemaphore, Lock

try:
	from impacket.dcerpc.v5 import transport, samr
except ImportError:
	print("You must install impacket before continuing")
	sys.exit(os.EX_SOFTWARE)

HELP_EPILOG = """
Enumerate the specified RID. If no password is entered, you will be prompted for one. Target IP must be the domain 
controller. In order to resolve DNS, you must specify the -d option.

Common RIDs:

Domain Computers:   515
Domain Controllers: 516
Domain Users:       513
Domain Admins:      512
Domain Guests:      514
Enterprise Admins:  519
"""


def impacket_compatibility(opts):
	opts.domain, opts.username, opts.password, opts.target = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(opts.target).groups('')

	#In case the password contains '@'
	if '@' in opts.target:
		opts.password = opts.password + '@' + opts.target.rpartition('@')[0]
		opts.target = opts.target.rpartition('@')[2]

	if opts.domain is None:
		opts.domain = ''

	if not opts.password and opts.username and not opts.no_pass:
		from getpass import getpass
		opts.password = getpass("Password:")


class SAMRGroupDump:
	def __init__(self, username, password, domain, target, rid, fqdn, dns_lookup, output, threads):
		self.username = username
		self.password = password
		self.domain = domain
		self.port = 445
		self.target = target
		self.fqdn = fqdn
		self.rid = rid
		self.dns_lookup = dns_lookup
		self.log = logging.getLogger('')
		self.output_file = ""
		self.data = []
		self.sem = BoundedSemaphore(threads)

		if output:
			if not (output).endswith(".txt"):
				output += ".txt"
			self.output_file = output

	@classmethod
	def from_args(cls, args):
		return cls(args.username, args.password, args.domain, args.target, args.rid, args.fqdn, args.dns_lookup, args.output, args.threads)

	def dump(self):
		self.log.info('[*] Retrieving endpoint list from {0}'.format(self.target))
		stringbinding = r'ncacn_np:{0}[\pipe\samr]'.format(self.target)
		logging.debug('StringBinding {0}'.format(stringbinding))
		rpctransport = transport.DCERPCTransportFactory(stringbinding)
		rpctransport.set_dport(self.port)
		rpctransport.setRemoteHost(self.target)

		if hasattr(rpctransport, 'set_credentials'):
			rpctransport.set_credentials(self.username, self.password, self.domain)

		self.__fetchlist(rpctransport)

	def __fetchlist(self, rpctransport):
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.bind(samr.MSRPC_UUID_SAMR)
		resp = samr.hSamrConnect(dce)
		serverHandle = resp['ServerHandle']
		resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
		domains = resp['Buffer']['Buffer']

		self.log.info('[+] Found domain: {0}'.format(domains[0]['Name']))
		self.log.info("[*] Enumerating RID {0} in the {1} domain..\n".format(self.rid, domains[0]['Name']))
		resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
		resp = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=resp['DomainId'])
		domainHandle = resp['DomainHandle']

		request = samr.SamrOpenGroup()
		request['DomainHandle'] = domainHandle
		request['DesiredAccess'] = samr.MAXIMUM_ALLOWED
		request['GroupId'] = self.rid

		try:
			resp = dce.request(request)
		except samr.DCERPCSessionError:
				raise

		request = samr.SamrGetMembersInGroup()
		request['GroupHandle'] = resp['GroupHandle']
		resp = dce.request(request)
		rids = resp.fields['Members'].fields['Data'].fields['Members'].fields['Data'].fields['Data']

		mutex = Lock()
		for rid in rids:
			self.sem.acquire()
			try:
				resp = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, rid.fields['Data'])
				rid_data = samr.hSamrQueryInformationUser2(dce, resp['UserHandle'], samr.USER_INFORMATION_CLASS.UserAllInformation)
			except samr.DCERPCSessionError as e:
				# Occasionally an ACCESS_DENIED is raised even though the user has permissions?
				# Other times a STATUS_NO_SUCH_USER is raised when a rid apparently doesn't exist, even though it reported back as existing.
				self.log.debug(e)
				continue
			if self.fqdn:
				rid_data = rid_data['Buffer']['All']['UserName'].replace('$', '') + '.' + self.fqdn
			else:
				rid_data = rid_data['Buffer']['All']['UserName'].replace('$', '')
			samr.hSamrCloseHandle(dce, resp['UserHandle'])

			if self.dns_lookup:
				# Threading because DNS lookups are slow
				t = Thread(target=self.get_ip, args=(rid_data, mutex,))
				t.start()
			else:
				self.log.info(rid_data)
				self.data.append(rid_data)
			self.sem.release()
		dce.disconnect()

	def get_ip(self, hostname, mutex):
		try:
			ip = socket.gethostbyname(hostname)
			rid_info = '{0}:{1}'.format(hostname, ip)
		except socket.error:
			rid_info = hostname

		with mutex:
			self.log.info(rid_info)
			self.data.append(rid_info)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(epilog=HELP_EPILOG, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-L', dest='loglvl', action='store', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help='set the logging level')
	parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<DC IP>')
	parser.add_argument('-o', dest='output', help='Output filename')
	parser.add_argument('-r', dest='rid', type=int, required=True, help='Enumerate the specified rid')
	parser.add_argument('-t', dest='threads', type=int, required=False, help='Maximum enumeration threads')
	parser.add_argument('-f', dest='fqdn',action='store', required=False, help='Provide the fully qualified domain')

	parser.add_argument('-d', dest='dns_lookup', default=False, action='store_true', help='Perform DNS lookup')
	parser.add_argument('-n', '--no-pass', dest='no_pass', action="store_true", help='don\'t ask for password')

	options = parser.parse_args()
	impacket_compatibility(options)
	logging.getLogger(logging.basicConfig(level=getattr(logging, options.loglvl), format=""))

	try:
		dumper = SAMRGroupDump.from_args(options)
		dumper.dump()
	except KeyboardInterrupt:
		print("Exiting...")

	except Exception as e:
		print(e)

	finally:
		if not options.output:
			sys.exit(os.EX_SOFTWARE)

		output_file = open(options.output, 'a+')
		for data in dumper.data:
			try:
				output_file.write(str(data) + '\n')
			except UnicodeEncodeError:
				continue
