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
from dns import resolver
from datetime import datetime
from threading import Thread, Lock
from time import strftime, gmtime
from logging.handlers import RotatingFileHandler

try:
	from impacket.dcerpc.v5 import transport, samr, lsad, lsat
	from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
	from impacket import nt_errors
except ImportError:
	print('You must install impacket before continuing')
	sys.exit(os.EX_SOFTWARE)

HELP_EPILOG = """
Enumerate the specified RID or string. If no password is entered you will be prompted for one (anonymous login is 
possible by substituting two single quotes in the username and pass field). Target IP must be the domain 
controller. In order to resolve DNS, you must specify the -d option. If you would like to enumerate all domain group
RIDs, use the -g option. To obtain all RIDs for every user in the domain (including descriptions), use the -u argument. 
If you don't know the RID you can use the -s option and specify the string name of the group/user/host and the RID will
be automatically discovered.

Note: Using the -s option creates two seperate connections to the target. This is because two rpctransports are
needed to resolve the RID from a string (lsar and samr). If you specify the RID the script will only perform a single 
connection to the domain controller. This isn't really important for general use but red teams may appreciate 
the insight.

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

	if not opts.nameservers:
		opts.nameservers = [opts.target]


class SAMRGroupDump:
	def __init__(self, username, password, domain, target, rid, fqdn, dns_lookup, output, nameservers):
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
		self.nameservers = nameservers
		self.data = []
		self.enumerate_groups = False
		self.enumerate_users = False
		self.enumerate_pass_policy = False

		log_handler = RotatingFileHandler('enumerid.log', maxBytes=5000000, backupCount=2)
		self.log.addHandler(log_handler)

		self.log.info('[*] Connection target: {0}'.format(self.target))

		if not len(nameservers) and self.dns_lookup:
			self.nameservers = [target]

		if output:
			if not output.endswith('.txt'):
				output += '.txt'
			self.output_file = output

	@classmethod
	def from_args(cls, args):
		return cls(args.username, args.password, args.domain, args.target, args.rid, args.fqdn, args.dns_lookup, args.output, args.nameservers)

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
	def convert_policy(low, high, lockout=False):
		# This method is from polenum.py
		time = ""
		tmp = 0

		if low == 0 and hex(high) == "-0x80000000":
			return "Not Set"
		if low == 0 and high == 0:
			return "None"

		if not lockout:
			if (low != 0):
				high = abs(high + 1)
			else:
				high = abs(high)
				low = abs(low)

			tmp = low + (high) * 16 ** 8  # convert to 64bit int
			tmp *= (1e-7)  # convert to seconds
		else:
			tmp = abs(high) * (1e-7)

		try:
			minutes = int(strftime("%M", gmtime(tmp)))
			hours = int(strftime("%H", gmtime(tmp)))
			days = int(strftime("%j", gmtime(tmp))) - 1
		except ValueError as e:
			return "[-] Invalid TIME"

		if days > 1:
			time += "{0} days ".format(days)
		elif days == 1:
			time += "{0} day ".format(days)
		if hours > 1:
			time += "{0} hours ".format(hours)
		elif hours == 1:
			time += "{0} hour ".format(hours)
		if minutes > 1:
			time += "{0} minutes ".format(minutes)
		elif minutes == 1:
			time += "{0} minute ".format(minutes)
		return time

	@staticmethod
	def attribute_bool(user, samr_user_hex):
		if user['UserAccountControl'] & samr_user_hex:
			attribute_active = 'No'
		else:
			attribute_active = 'Yes'

		return attribute_active

	def dump(self):
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
							username = user['AccountName']
							full_name = user['FullName']
							admin_comment = user['AdminComment']
							rid = user['Rid']
						except AttributeError:
							pass
						try:
							data = '{0},{1},{2},{3}'.format(rid, username, full_name, admin_comment)
						except UnboundLocalError:
							continue
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
		self.log.info('[*] Group RID detected. Enumerating all members and any additional groups..\n')
		# If we find group RIDs within a group, we will append it to this list and enumerate that too.
		group_rids = list()
		group_rids.append(self.rid)

		for group_rid in group_rids:
			request = samr.SamrOpenGroup()
			request['DomainHandle'] = domain_handle
			request['DesiredAccess'] = samr.GENERIC_READ
			request['GroupId'] = group_rid

			try:
				resp = dce.request(request)
			except samr.DCERPCSessionError:
					raise

			request = samr.SamrGetMembersInGroup()
			request['GroupHandle'] = resp['GroupHandle']
			resp = dce.request(request)

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
					# Other times a STATUS_NO_SUCH_USER is raised when a rid apparently doesn't exist, even though it reported back as existing. Maybe a group? Let's try to enumerate it later
					if 'STATUS_NO_SUCH_USER' in str(e):
						group_rids.append(rid['Data'])
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

	def enumerate_password_policy(self, dce, domain_handle):
		# This method is a refactored and cleaned up version of polenum.py. I had a hard time finding the true
		# author of polenum.py to give credit.. Give me a shout if you're out there!
		domain_passwd = samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
		resp = samr.hSamrQueryInformationDomain2(dce, domainHandle=domain_handle, domainInformationClass=domain_passwd)
		policy = resp['Buffer']['Password']
		minimum_len = policy['MinPasswordLength'] or "None"
		history = policy['PasswordHistoryLength'] or "None"
		maximum_age = self.convert_policy(int(policy['MaxPasswordAge']['LowPart']), int(policy['MaxPasswordAge']['HighPart']))
		minimum_pass_age = self.convert_policy(int(policy['MinPasswordAge']['LowPart']), int(policy['MinPasswordAge']['HighPart']))
		password_props = policy['PasswordProperties']

		complexity_binary = []
		while password_props:
			complexity_binary.append(password_props % 2)
			password_props /= 2

		com_binary = complexity_binary[::-1]
		if len(com_binary) != 8:
			for x in xrange(6 - len(com_binary)):
				com_binary.insert(0, 0)
		password_props = ''.join([str(value) for value in com_binary])

		domain_lockout = samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
		resp = samr.hSamrQueryInformationDomain2(dce, domainHandle=domain_handle, domainInformationClass=domain_lockout)
		lockout = resp['Buffer']['Lockout']
		lockout_observation = self.convert_policy(0, lockout['LockoutObservationWindow'], lockout=True)
		lockout_duration = self.convert_policy(0, lockout['LockoutDuration'], lockout=True)
		lockout_threshold = lockout['LockoutThreshold'] or "None"

		domain_logoff = samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation
		resp = samr.hSamrQueryInformationDomain2(dce, domainHandle=domain_handle, domainInformationClass=domain_logoff)
		logoff = resp['Buffer']['Logoff']['ForceLogoff']
		logoff_time = self.convert_policy(logoff['LowPart'], logoff['HighPart'])

		domain_complexity = {
			5: 'Domain Password Complex:',
			4: 'Domain Password No Anon Change:',
			3: 'Domain Password No Clear Change:',
			2: 'Domain Password Lockout Admins:',
			1: 'Domain Password Store Cleartext:',
			0: 'Domain Refuse Password Change:'
		}

		self.log.info("\n\t[+] Minimum password length: {0}".format(minimum_len))
		self.log.info("\t[+] Password history length: {0}".format(history))
		self.log.info("\t[+] Maximum password age: {0}".format(maximum_age))
		self.log.info("\t[+] Password Complexity Flags: {0}\n".format(password_props or "None"))

		for i, a in enumerate(password_props):
			self.log.info("\t\t[+] {0} {1}".format(domain_complexity[i], str(a)))

		self.log.info("\n\t[+] Minimum password age: {0}".format(minimum_pass_age))
		self.log.info("\t[+] Reset Account Lockout Counter: {0}".format(lockout_observation))
		self.log.info("\t[+] Locked Account Duration: {0}".format(lockout_duration))
		self.log.info("\t[+] Account Lockout Threshold: {0}".format(lockout_threshold))
		self.log.info("\t[+] Forced Log off Time: {0}\n".format(logoff_time))

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

		elif self.enumerate_pass_policy:
			self.log.info('[*] Enumerating domain password policy')
			self.enumerate_password_policy(dce, domain_handle)

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
		res = resolver.Resolver()
		res.nameservers = self.nameservers 
		try:
			answers = res.query(hostname)
			if len(answers):
				ip = answers[0].address
			else:
				ip = ''
			rid_info = '{0},{1}'.format(hostname, ip)
		except Exception:
			rid_info = hostname

		with mutex:
			self.log.info(rid_info)
			self.data.append(rid_info.encode('utf-8'))

	def get_sid(self, name):
		self.log.info('[*] Looking up SID for {0}..'.format(name))
		stringbinding = r'ncacn_np:{0}[\pipe\lsarpc]'.format(self.target)
		logging.debug('StringBinding {0}'.format(stringbinding))
		rpctransport = transport.DCERPCTransportFactory(stringbinding)
		rpctransport.set_dport(self.port)
		rpctransport.setRemoteHost(self.target)

		if hasattr(rpctransport, 'set_credentials'):
			rpctransport.set_credentials(self.username, self.password, self.domain)

		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.bind(lsat.MSRPC_UUID_LSAT)
		resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsad.POLICY_LOOKUP_NAMES)
		policyHandle = resp['PolicyHandle']
		resp = lsat.hLsarLookupNames(dce, policyHandle, (name,))
		self.rid = resp['TranslatedSids']['Sids'][0]['RelativeId']
		dce.disconnect()
		return


if __name__ == '__main__':
	parser = argparse.ArgumentParser(epilog=HELP_EPILOG, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-L', dest='loglvl', action='store', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help='set the logging level')
	parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<DC IP>')
	parser.add_argument('-o', dest='output', help='Output filename')
	parser.add_argument('-r', dest='rid', default=0, help='Enumerate the specified rid')
	parser.add_argument('-f', dest='fqdn',action='store', required=False, help='Provide the fully qualified domain')
	parser.add_argument('-d', dest='dns_lookup', default=False, action='store_true', help='Perform DNS lookup')
	parser.add_argument('-n', '--no-pass', dest='no_pass', action='store_true', help='don\'t ask for password')
	parser.add_argument('-ns', '--nameservers', dest='nameservers', nargs='+', default=[], help='Specify alternate nameserver for DNS resolution. Default: target-dc')
	parser.add_argument('-g', dest='enum_groups', default=False, action='store_true', help='Enumerate all Domain Group RIDs')
	parser.add_argument('-u', dest='enum_users', default=False, action='store_true', help='Enumerate all Domain User RIDs, name and descriptions')
	parser.add_argument('-p', dest='enum_pass_policy', default=False, action='store_true', help='Enumerate domain password policy')
	parser.add_argument('-s', dest='string_name', action='store', required=False, help='Lookup RID for the specified string and enumerate information')

	options = parser.parse_args()
	impacket_compatibility(options)
	logging.getLogger(logging.basicConfig(level=getattr(logging, options.loglvl), format=''))

	if options.rid == 0 and not options.enum_groups and not options.enum_users and not options.string_name and not options.enum_pass_policy:
		print('[-] You must specify a RID (-r) or enumerate all domain groups (-g) or enumerate all domain users (-u) or string name (-s) or enumerate password policy (-p)')
		sys.exit(os.EX_SOFTWARE)
	try:
		dumper = SAMRGroupDump.from_args(options)
		dumper.enumerate_groups = options.enum_groups
		dumper.enumerate_users = options.enum_users
		dumper.enumerate_pass_policy = options.enum_pass_policy

		if options.string_name:
			dumper.get_sid(options.string_name)
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
				if isinstance(data, bytes):
					data = data.decode()
				output_file.write(data + '\n')
			except UnicodeEncodeError:
				continue
