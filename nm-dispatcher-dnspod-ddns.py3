#!/usr/bin/env python3

config = {
	'ipv4': {
		'enable': True,
		'interface': 'x',
		'domain': 'x',
		'subdomain': 'x',
		'line': '默认',
		'email': 'x',
		'password': 'x'
	},
	'ipv6': {
		'enable': True,
		'interface': 'x',
		'domain': 'x',
		'subdomain': 'x',
		'line': '默认',
		'email': 'x',
		'password': 'x'
	},
	'host': 'https://dnsapi.cn/',
	'debug': True
}

###############################################################################

import sys
import os
import ipaddress
import subprocess
import re
import requests


def check_ip(ip):
	try:
		ipobj = ipaddress.ip_address(ip)
	except ValueError:
		return False

	if isinstance(ipobj, ipaddress.IPv4Address):
		return not(ipobj.is_private or
			ipobj.is_unspecified or
			ipobj.is_reserved or
			ipobj.is_loopback or
			ipobj.is_link_local or
			ipobj.is_multicast)
	elif isinstance(ipobj, ipaddress.IPv6Address):
		return not(ipobj.is_private or
			ipobj.is_unspecified or
			ipobj.is_reserved or
			ipobj.is_loopback or
			ipobj.is_link_local or
			ipobj.is_multicast or
			ipobj.is_site_local or
			(ipobj.ipv4_mapped is not None))


def get_first_ip(ips):
	for ip in ips:
		if check_ip(ip):
			return ip
	return None


def _check_error(json, msg):
	if int(json['status']['code']) != 1:
		raise RuntimeError(msg + str(json['status']['code']) +
			' - ' + json['status']['message'])


def _get_domain_id(config, domain, common_payload):
	payload = common_payload.copy()
	payload['domain'] = domain
	r = requests.post(config['host'] + 'Domain.Info', data = payload)
	j = r.json()
	_check_error(j, '[Error_Domain] ')
	return int(j['domain']['id'])


def _get_record(config, domain_id, subdomain, record_type, line, common_payload):
	payload = common_payload.copy()
	payload['domain_id'] = domain_id
	payload['sub_domain'] = subdomain
	r = requests.post(config['host'] + 'Record.List', data = payload)
	j = r.json()
	_check_error(j, '[Error_Record] ')
	for rec in j['records']:
		if rec['name'] == subdomain and \
				rec['type'] == record_type and \
				rec['line'] == line:
			return int(rec['id']), rec['value']
	raise RuntimeError('[Error_Record] Record not found!')


def _set_record(config, domain_id, record_id,
		subdomain, record_type, record_line, newvalue, common_payload):
	payload = common_payload.copy()
	payload['domain_id'] = domain_id
	payload['record_id'] = record_id
	payload['sub_domain'] = subdomain
	payload['record_type'] = record_type
	payload['record_line'] = record_line
	payload['value'] = newvalue
	r = requests.post(config['host'] + 'Record.Modify', data = payload)
	j = r.json()
	_check_error(j, '[Error_Update] ')
	return True


def update_ddns(config, is_ipv6, address):
	info = lambda msg: print(msg) if config['debug'] else None
	if not is_ipv6:
		config_section = config['ipv4']
		record_type = 'A'
	else:
		config_section = config['ipv6']
		record_type = 'AAAA'

	common_payload = {
		'login_email': config_section['email'],
		'login_password': config_section['password'],
		'format': 'json',
		'lang': 'en',
		'error_on_empty': 'yes'
	}

	try:
		# first get domain ID
		domain_id = _get_domain_id(config,
			config_section['domain'],
			common_payload)
		# then get record ID and current value
		record_id, record_value = _get_record(config,
			domain_id,
			config_section['subdomain'],
			record_type,
			config_section['line'],
			common_payload)
		# if need updating, update it
		if record_value != address:
			_set_record(config,
				domain_id,
				record_id,
				config_section['subdomain'],
				record_type,
				config_section['line'],
				address,
				common_payload)
			info('Update successful')
		else:
			info('No need to update')
		return True
	except RuntimeError as err:
		info('ERROR ' + str(err))
		return False


def _extract_ip(line, restr):
	r = re.findall(restr, line)
	return len(r)>0 ? r[0] : None


def _get_ifconfig(interface_name, keyword, restr):
	ret = subprocess.check_output(['env LANG=C LC_ALL=C ifconfig', interface_name],
		universal_newlines=True)
	lines = ret.splitlines()
	results = []
	for line in lines:
		line = line.replace('  ', ' ').strip()
		tokens = line.split(' ')
		if tokens[0] == keyword:
			results.append(tokens[1])
			ip = _extract_ip(line, restr)
			if ip:
				results.append(ip)
	return results


def handle_ip(config, interface_name, action, is_ipv6):
	info = lambda msg: print(msg) if config['debug'] else None
	if not is_ipv6:
		config_section = config['ipv4']
		ignore_action = 'dhcp6-change'
		env_prefix = 'IP4'
		ifconfig_keyword = 'inet'
		ifconfig_restr = '((?:\d{1,3}\.){3}\d{1,3})'
	else:
		config_section = config['ipv6']
		ignore_action = 'dhcp4-change'
		env_prefix = 'IP6'
		ifconfig_keyword = 'inet6'
		ifconfig_restr = '((?:[\dA-Fa-f]{,4}\:){2,7}[\dA-Fa-f]{,4})'

	info('Working with ' + env_prefix)
	if interface_name != config_section['interface']:
		info('Interface mismatch: ' + interface_name)
		return False

	if config_section['enable'] and action != ignore_action:
		ip_num_addresses = int(os.getenv(env_prefix + '_NUM_ADDRESSES', 0))
		info('Got ' + str(ip_num_addresses) + ' address(es)')
		ip_address = []
		# Get address from env
		if ip_num_addresses != 0:
			for i in range(ip_num_addresses):
				ip = os.getenv(env_prefix + '_ADDRESS_' + str(i), None)
				if ip is not None:
					if '/' in ip:
						ip = ip[:ip.index('/')]
					ip_address.append(ip)
		# Get address by ifconfig
		ip_address.extend(_get_ifconfig(
			config_section['interface'],
			ifconfig_keyword, ifconfig_restr))
		info('They are: ' + repr(ip_address))
		valid_ip = get_first_ip(ip_address)
		if valid_ip is not None:
			info('Updating with valid address: ' + valid_ip)
			update_ddns(config, is_ipv6, valid_ip)
			return True
		else:
			info('All invalid. What a disappointment.')

	return False


def main(config):
	info = lambda msg: print(msg) if config['debug'] else None

	interface_name = sys.argv[1]

	action = sys.argv[2]
	if action not in ['up', 'dhcp4-change', 'dhcp6-change']:
		info('Dont care about this action: ' + action)
		return 1

	info('Dispatcher on interface: ' + interface_name + '; Action: ' + action)

	# Handle IPv4
	handle_ip(config, interface_name, action, False)
	# Handle IPv6
	handle_ip(config, interface_name, action, True)



if __name__ == '__main__':
	main(config)