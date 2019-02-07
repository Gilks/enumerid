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
from datetime import datetime

try:
	from impacket.dcerpc.v5 import transport, samr
	from impacket import nt_errors
except ImportError:
	print('You must install impacket before continuing')
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
		opts.password = getpass('Password:')


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
		self.output_file = ''
		self.data = []
		self.enumerate_groups = False
		self.enumerate_users = False

		if output:
			if not (output).endswith('.txt'):
				output += '.txt'
			self.output_file = output

	@classmethod
	def from_args(cls, args):
		return cls(args.username, args.password, args.domain, args.target, args.rid, args.fqdn, args.dns_lookup, args.output)

	@staticmethod
	def get_unix_time(time):
		time -= 116444736000000000
		time /= 10000000
		return time

	def expiration_check(self, user, attribute_str):
		attribute = (user[attribute_str]['HighPart'] << 32) + user[attribute_str]['LowPart']
		if not attribute:
			attribute = 'Never'
		else:
			try:
				attribute = str(datetime.fromtimestamp(self.get_unix_time(attribute)))
			except ValueError:
				attribute = 'Never'

		return attribute

	@staticmethod
	def attribute_bool(user, samr_user_hex):
		if user['UserAccountControl'] & samr_user_hex:
			attribute_active = 'No'
		else:
			attribute_active = 'Yes'

		return attribute_active

	def dump(self):
		self.log.info('[*] Retrieving endpoint list from {0}'.format(self.target))
		stringbinding = r'ncacn_np:{0}[\pipe\samr]'.format(self.target)
		logging.debug('StringBinding {0}'.format(stringbinding))
		rpctransport = transport.DCERPCTransportFactory(stringbinding)
		rpctransport.set_dport(self.port)
		rpctransport.setRemoteHost(self.target)

		if hasattr(rpctransport, 'set_credentials'):
			rpctransport.set_credentials(self.username, self.password, self.domain)

		self.initialize_dce(rpctransport)

	def enumerate_domain_groups(self, dce, domain_handle):
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
					groups = resp['Buffer']['Buffer']
					for i, group in enumerate(groups):
						rid = resp['Buffer']['Buffer'][i]['RelativeId']
						group_name = (resp['Buffer']['Buffer'][i]['Name']).encode('utf8')
						group_and_rid = ('{0},{1}'.format(group_name, rid))
						self.log.info(group_and_rid)
						self.data.append(group_and_rid)
					continue
			break

	def enumerate_domain_users(self, dce, domain_handle):
		request = samr.SamrQueryDisplayInformation()
		request['DomainHandle'] = domain_handle
		request['DisplayInformationClass'] = samr.DOMAIN_DISPLAY_INFORMATION.DomainDisplayUser
		request['Index'] = 0
		request['EntryCount'] = 0xffffffff
		request['PreferredMaximumLength'] = 0xffffffff
		count = 0

		while True:
			try:
				resp = dce.request(request)
			except Exception as dce_exception:
				if dce_exception.error_code == nt_errors.STATUS_MORE_ENTRIES:
					resp = dce_exception.get_packet()
					count += resp['Buffer']['UserInformation']['EntriesRead']
					request['Index'] = count
					users = resp['Buffer']['UserInformation']['Buffer']
					for i, user in enumerate(users):
						try:
							username = (user['AccountName']).encode('utf8')
							full_name = (user['FullName']).encode('utf8')
							admin_comment = (user['AdminComment']).encode('utf8')
							rid = user['Rid']
						except AttributeError:
							pass

						data = '{0},{1},{2},{3}'.format(rid, username, full_name, admin_comment)
						self.log.info(data)
						self.data.append(data)
					continue
			break

	def enumerate_user_info(self, dce, domain_handle):
		# Most of this method was built using logic from samrdump.py
		user_request = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, self.rid)
		self.log.info('[*] User RID detected. Enumerating information on user..\n')
		info = samr.hSamrQueryInformationUser(dce, user_request['UserHandle'], samr.USER_INFORMATION_CLASS.UserAllInformation)
		user = info['Buffer']['All']

		pass_last_set = self.expiration_check(user, 'PasswordLastSet')
		account_expires = self.expiration_check(user, 'AccountExpires')
		pass_expires = self.expiration_check(user, 'PasswordMustChange')
		pass_can_change = self.expiration_check(user, 'PasswordCanChange')
		last_logon = self.expiration_check(user, 'LastLogon')
		account_active = self.attribute_bool(user, samr.USER_ACCOUNT_DISABLED)
		user_may_change_pass = self.attribute_bool(user, samr.USER_CHANGE_PASSWORD)
		password_required = self.attribute_bool(user, samr.USER_PASSWORD_NOT_REQUIRED)

		workstations_allowed = user['WorkStations']

		if workstations_allowed == '':
			workstations_allowed = 'All'

		self.log.info('User name\t\t\t{0}'.format(user['UserName']))
		self.log.info('User RID\t\t\t{0}'.format(user['UserId']))
		self.log.info('Full Name\t\t\t{0}'.format(user['FullName']))
		self.log.info('Comment\t\t\t\t{0}'.format(user['AdminComment']))
		self.log.info("User's Comment\t\t\t\t{0}".format(user['UserComment']))
		self.log.info('Country/region code\t\t{0}'.format(user['CountryCode']))
		self.log.info('Account active\t\t\t{0}'.format(account_active))
		self.log.info('Account expires\t\t\t{0}\n'.format(account_expires))

		self.log.info('Password last set\t\t{0}'.format(pass_last_set))
		self.log.info('Password expires\t\t{0}'.format(pass_expires))
		self.log.info('Password changeable\t\t{0}'.format(pass_can_change))
		self.log.info('Password required\t\t{0}'.format(password_required))
		self.log.info('Bad Password Count\t\t{0}'.format(user['BadPasswordCount']))
		self.log.info('User may change password\t{0}\n'.format(user_may_change_pass))

		self.log.info('Workstations allowed\t\t{0}'.format(workstations_allowed))
		self.log.info('Logon script\t\t\t\t{0}'.format(user['ScriptPath']))
		self.log.info('User profile\t\t\t\t{0}'.format(user['ProfilePath']))
		self.log.info('Home directory\t\t\t{0}'.format(user['HomeDirectory']))
		self.log.info('Home directory drive\t\t{0}\n'.format(user['HomeDirectoryDrive']))

		self.log.info('Group Memberships')
		group_rids = samr.hSamrGetGroupsForUser(dce, user_request['UserHandle'])['Groups']['Groups']

		for i, group_rid in enumerate(group_rids):
			group_rid = group_rids[i]['RelativeId']
			group_request = samr.hSamrOpenGroup(dce, domain_handle, samr.MAXIMUM_ALLOWED, group_rid)
			group_info = samr.hSamrQueryInformationGroup(dce, group_request['GroupHandle'])
			group_name = group_info['Buffer']['General']['Name']
			group_comment = group_info['Buffer']['General']['AdminComment']
			self.log.info('Name: {0}\nDesc: {1}\n'.format(group_name, group_comment))

		samr.hSamrCloseHandle(dce, user_request['UserHandle'])
		samr.hSamrCloseHandle(dce, group_request['GroupHandle'])

	def enumerate_users_in_group(self, dce, domain_handle):
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
		self.log.info('[*] Group RID detected. Enumerating users in group..\n')

		try:
			rids = resp['Members']['Members']
		except AttributeError:
			self.log.info('[-] No users in group')
			return

		mutex = Lock()
		for rid in rids:
			try:
				resp = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, rid['Data'])
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

	def initialize_dce(self, rpctransport):
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.bind(samr.MSRPC_UUID_SAMR)
		resp = samr.hSamrConnect(dce)
		server_handle = resp['ServerHandle']
		resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
		domains = resp['Buffer']['Buffer']

		self.log.info('[+] Found domain: {0}'.format(domains[0]['Name']))
		resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domains[0]['Name'])
		resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=resp['DomainId'])
		domain_handle = resp['DomainHandle']

		if self.enumerate_groups:
			self.log.info('[*] Enumerating all Domain Group RIDs (Group/RID)')
			self.enumerate_domain_groups(dce, domain_handle)

		elif self.enumerate_users:
			self.log.info('[*] Enumerating all Domain Users (RID/Username/Name/Description)')
			self.enumerate_domain_users(dce, domain_handle)

		else:
			self.log.info('[*] Enumerating RID {0} in the {1} domain..'.format(self.rid, domains[0]['Name']))
			try:
				self.enumerate_user_info(dce, domain_handle)
				dce.disconnect()
				return
			except samr.DCERPCSessionError:
				self.log.debug('[*] RID is not for a user. Trying again as a group.')
				pass

			try:
				self.enumerate_users_in_group(dce, domain_handle)
			except samr.DCERPCSessionError:
				self.log.debug('[*] RID is not for a group either')
				self.log.info('[-] RID not found')

		dce.disconnect()

	def get_ip(self, hostname, mutex):
		try:
			ip = socket.gethostbyname(hostname)
			rid_info = '{0},{1}'.format(hostname, ip)
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
	parser.add_argument('-r', dest='rid', default=0, help='Enumerate the specified rid')
	parser.add_argument('-f', dest='fqdn',action='store', required=False, help='Provide the fully qualified domain')
	parser.add_argument('-d', dest='dns_lookup', default=False, action='store_true', help='Perform DNS lookup')
	parser.add_argument('-n', '--no-pass', dest='no_pass', action='store_true', help='don\'t ask for password')
	parser.add_argument('-g', dest='enum_groups', default=False, action='store_true', help='Enumerate all Domain Group RIDs')
	parser.add_argument('-u', dest='enum_users', default=False, action='store_true', help='Enumerate all Domain User RIDs, name and descriptions')

	options = parser.parse_args()
	impacket_compatibility(options)
	logging.getLogger(logging.basicConfig(level=getattr(logging, options.loglvl), format=''))

	if options.rid == 0 and not options.enum_groups and not options.enum_users:
		print('[-] You must specify a RID (-r) or enumerate all domain groups (-g) or enumerate all domain users (-u)')
		sys.exit(os.EX_SOFTWARE)
	try:
		dumper = SAMRGroupDump.from_args(options)
		dumper.enumerate_groups = options.enum_groups
		dumper.enumerate_users = options.enum_users
		dumper.dump()
	except KeyboardInterrupt:
		print('Exiting...')

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
