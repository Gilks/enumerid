#!/usr/bin/python2
#
#  enumerid.py
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
from threading import Thread, Lock

try:
	from impacket.dcerpc.v5 import transport, samr
	from impacket import nt_errors
except ImportError:
	print("You must install impacket before continuing")
	sys.exit(os.EX_SOFTWARE)

HELP_EPILOG = """
Enumerate the specified RID. If no password is entered, you will be prompted for one. Target IP must be the domain 
controller. In order to resolve DNS, you must specify the -d option. If you would like to enumerate all domain group
RIDs for your domain, use the -g option.

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
	# In case the password contains '@'
	if '@' in opts.target:
		opts.password = opts.password + '@' + opts.target.rpartition('@')[0]
		opts.target = opts.target.rpartition('@')[2]

	if opts.domain is None:
		opts.domain = ''

	if not opts.password and opts.username and not opts.no_pass:
		from getpass import getpass
		opts.password = getpass("Password:")


class SAMRGroupDump:
	def __init__(self, username, password, domain, target, rid, fqdn, dns_lookup, output):
		self.username = username
		self.password = password
		self.domain = domain
		self.port = 445
		self.target = target
		self.fqdn = fqdn
		self.rid = int(rid)
		self.dns_lookup = dns_lookup
		self.log = logging.getLogger('')
		self.output_file = ""
		self.data = []
		self.enumerate_groups = False

		if output:
			if not (output).endswith(".txt"):
				output += ".txt"
			self.output_file = output

	@classmethod
	def from_args(cls, args):
		return cls(args.username, args.password, args.domain, args.target, args.rid, args.fqdn, args.dns_lookup, args.output)

	def dump(self):
		self.log.info('[*] Retrieving endpoint list from {0}'.format(self.target))
		stringbinding = r'ncacn_np:{0}[\pipe\samr]'.format(self.target)
		logging.debug('StringBinding {0}'.format(stringbinding))
		rpctransport = transport.DCERPCTransportFactory(stringbinding)
		rpctransport.set_dport(self.port)
		rpctransport.setRemoteHost(self.target)

		if hasattr(rpctransport, 'set_credentials'):
			rpctransport.set_credentials(self.username, self.password, self.domain)

		self.__initialize_dce(rpctransport)

	def __enumerate_domain_groups(self, dce, domain_handle):
		request = samr.SamrEnumerateGroupsInDomain()
		request['DomainHandle'] = domain_handle
		request['EnumerationContext'] = 0
		request['PreferedMaximumLength'] = 0xffffffff

		while True:
			try:
				resp = dce.request(request)
			except Exception as dce_exception:
				if dce_exception.error_code == nt_errors.STATUS_MORE_ENTRIES:
					resp = dce_exception.get_packet()
					request['EnumerationContext'] = resp['EnumerationContext']
					groups = resp['Buffer'].fields['Buffer'].fields['Data'].fields['Data']
					for i, group in enumerate(groups):
						rid = resp['Buffer'].fields['Buffer'].fields['Data'].fields['Data'][i].fields['RelativeId'].fields['Data']
						group_name = (resp['Buffer'].fields['Buffer'].fields['Data'].fields['Data'][i].fields['Name'].fields['Data'].fields['Data'].fields['Data']).decode('utf-16').encode("utf8")
						group_and_rid = ('{0}:{1}'.format(group_name, rid))
						self.log.info(group_and_rid)
						self.data.append(group_and_rid)
					continue
			break

	def __enumerate_users_in_group(self, dce, domain_handle):
		request = samr.SamrOpenGroup()
		request['DomainHandle'] = domain_handle
		request['DesiredAccess'] = samr.MAXIMUM_ALLOWED
		request['GroupId'] = self.rid

		try:
			resp = dce.request(request)
		except samr.DCERPCSessionError:
				raise

		request = samr.SamrGetMembersInGroup()
		request['GroupHandle'] = resp['GroupHandle']
		resp = dce.request(request)

		try:
			rids = resp.fields['Members'].fields['Data'].fields['Members'].fields['Data'].fields['Data']
		except AttributeError:
			self.log.info('[-] No users in group')
			return

		mutex = Lock()
		for rid in rids:
			try:
				resp = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, rid.fields['Data'])
				rid_data = samr.hSamrQueryInformationUser2(dce, resp['UserHandle'], samr.USER_INFORMATION_CLASS.UserAllInformation)
			except samr.DCERPCSessionError as e:
				# Occasionally an ACCESS_DENIED is rasied even though the user has permissions?
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

	def __initialize_dce(self, rpctransport):
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.bind(samr.MSRPC_UUID_SAMR)
		resp = samr.hSamrConnect(dce)
		server_handle = resp['ServerHandle']
		resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
		domains = resp['Buffer']['Buffer']

		self.log.info('[+] Found domain: {0}'.format(domains[0]['Name']))
		self.log.info("[*] Enumerating RID {0} in the {1} domain..\n".format(self.rid, domains[0]['Name']))
		resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domains[0]['Name'])
		resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=resp['DomainId'])
		domain_handle = resp['DomainHandle']

		if self.enumerate_groups:
			self.__enumerate_domain_groups(dce, domain_handle)
		else:
			self.__enumerate_users_in_group(dce, domain_handle)
		dce.disconnect()

	def get_ip(self, hostname, mutex):
		try:
			ip = socket.gethostbyname(hostname)
			rid_info = '{0}:{1}'.format(hostname, ip)
		except socket.error:
			rid_info = hostname

		with mutex:
			self.log.info(rid_info)
			self.data.append(rid_info.encode('utf-8'))


if __name__ == '__main__':
	parser = argparse.ArgumentParser(epilog=HELP_EPILOG, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-L', dest='loglvl', action='store', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help='set the logging level')
	parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<DC IP>')
	parser.add_argument('-o', dest='output', help='Output filename')
	parser.add_argument('-r', dest='rid', help='Enumerate the specified rid')
	parser.add_argument('-f', dest='fqdn',action='store', required=False, help='Provide the fully qualified domain')
	parser.add_argument('-d', dest='dns_lookup', default=False, action='store_true', help='Perform DNS lookup')
	parser.add_argument('-n', '--no-pass', dest='no_pass', action="store_true", help='don\'t ask for password')
	parser.add_argument('-g', dest='enum_groups', default=False, action="store_true", help='Enumerate all Domain Group RIDs')

	options = parser.parse_args()
	impacket_compatibility(options)
	logging.getLogger(logging.basicConfig(level=getattr(logging, options.loglvl), format=""))

	if not options.rid and not options.enum_groups:
		print("[-] You must specify a RID (-r) or enumerate all domain groups (-g)")
		sys.exit(os.EX_SOFTWARE)
	try:
		dumper = SAMRGroupDump.from_args(options)
		dumper.enumerate_groups = options.enum_groups
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
				output_file.write(data + '\n')
			except UnicodeEncodeError:
				continue
