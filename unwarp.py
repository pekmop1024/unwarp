#!/usr/bin/env python

'''
parse cloudflare warp configuration and create .nmconnection basing on it
'''

import os
import re
import sys
import json
import logging
import argparse
from subprocess import Popen, PIPE
from configparser import ConfigParser

LOG = logging.getLogger(__name__)

def parse_args():
    '''
    parse all the command line arguments
    '''
    help_desc = 'get and set routes from cloudflare warp for usage with vanilla wireguard'
    arguments = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                        description=help_desc)
    arguments.add_argument('-d',
                           '--debug',
                           action='store_true',
                           help='enable debug output')
    arguments.add_argument('-D',
                           '--dry-run',
                           action='store_true',
                           help='dry run')
    arguments.add_argument('-z',
                           '--warpconfig',
                           help='path to warp configuration file',
                           default='/var/lib/cloudflare-warp/conf.json')
    arguments.add_argument('-w',
                           '--wgconfig',
                           help='path to warp registration file (default location needs root for reading)',
                           default='/var/lib/cloudflare-warp/reg.json')
    arguments.add_argument('-i',
                           '--interface',
                           help='wireguard interface name',
                           required=True)
    arguments.add_argument('-n',
                           '--nmconnectionname',
                           help='networkmanager connection name',
                           required=True)
    arguments.add_argument('-s',
                           '--domainsearch',
                           help='domains search for connection (space-separated list of domain names)',
                           default=None)
    arguments.add_argument('-c',
                           '--nmconnectionpath',
                           help='networkmanager connections path (default location needs root for writing)',
                           default='/etc/NetworkManager/system-connections')
    arguments.add_argument('-4',
                           '--ipv4only',
                           action='store_true',
                           help='ipv4 routes only')
    arguments.add_argument('-f',
                           '--overwrite',
                           action='store_true',
                           help='overwrite networkmanager connection configuration file')
    arguments.add_argument('-r',
                           '--nmreload',
                           action='store_true',
                           help='reload networkmanager configuration')

    args, _ = arguments.parse_known_args()
    return args

def configure_logging(debug, dry_run):
    '''
    set up logging
    '''
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logger = logging.getLogger()
    logger.setLevel(log_level)
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(log_level)
    if dry_run:
        formatter = logging.Formatter('%(levelname)-8s- DRY RUN: %(message)s')
    else:
        formatter = logging.Formatter('%(levelname)-8s- %(message)s')
    console.setFormatter(formatter)
    logger.addHandler(console)

def shell_command(cmdline):
    '''
    execute shell command and return dict with exit code, stdout and stderr
    '''
    exitcode = 1
    stdout = b''
    stderr = b''
    LOG.debug('shell command: %s',
              cmdline)
    with Popen(cmdline, shell=True, stdout=PIPE, stderr=PIPE) as cmd:
        exitcode = cmd.wait()
        stdout, stderr = cmd.communicate()
    LOG.debug('shell command exit code: %s',
              exitcode)
    LOG.debug('shell command stdout: %s',
              stdout)
    LOG.debug('shell command stderr: %s',
              stderr)
    return {'exitcode': exitcode, 'stdout': stdout, 'stderr': stderr}

def valid_ipv4(ipv4):
    '''
    Check if input string is valid IPv4 address
    '''
    result = False
    if len(str(ipv4)) < 16 and str(ipv4).count('.') == 3:
        if [0<=int(x)<256 for x in re.split('\\.', re.match(r'^\d+\.\d+\.\d+\.\d+$', ipv4).group(0))].count(True) == 4:
            result = True
    return result

def read_json(config_file):
    '''
    read config file
    '''
    if os.path.isfile(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as json_config:
                config = json.load(json_config)
        except PermissionError:
            LOG.info('can not read file, insufficient permissions: %s',
                     config_file)
            raise IOError from PermissionError
    else:
        LOG.debug('failed to read file: %s',
                  config_file)
        LOG.info('please supply correct path to file, exiting')
        raise IOError
    LOG.info('reading file: %s',
             config_file)
    return config

def get_routes(warpconfig):
    '''
    get routes list from cloudflare warp configuration
    '''
    routes4 = ['1.1.1.1/32']
    routes6 = []
    if 'policy' in warpconfig:
        for raw_route in warpconfig['policy']['include']:
            if 'address' in raw_route:
                if valid_ipv4(raw_route['address'].split('/')[0]):
                    routes4.append(raw_route['address'])
                else:
                    routes6.append(raw_route['address'])
    return routes4, routes6

def create_nm_config(warpconfig, wgconfig, ifname, nmname, ipv4only, dnssearch):
    '''
    create networkmanager wireguard connection from cloudflare warp config
    '''
    nmconfig = ConfigParser()
    routes4, routes6 = get_routes(warpconfig)
    nmconfig.add_section('connection')
    nmconfig.add_section('wireguard')
    nmconfig.add_section(f'wireguard-peer.{warpconfig["public_key"]}')
    nmconfig.add_section('ipv6')
    nmconfig.add_section('ipv4')
    nmconfig.add_section('proxy')
    nmconfig.set('connection', 'id', nmname)
    nmconfig.set('connection', 'type', 'wireguard')
    nmconfig.set('connection', 'autoconnect', 'false')
    nmconfig.set('connection', 'interface-name', ifname)
    nmconfig.set('wireguard', 'mtu', '1280')
    nmconfig.set('wireguard', 'peer-routes', 'false')
    nmconfig.set('wireguard', 'private-key', wgconfig["secret_key"])
    nmconfig.set(f'wireguard-peer.{warpconfig["public_key"]}', 'endpoint', warpconfig["endpoints"][0]["v4"])
    nmconfig.set(f'wireguard-peer.{warpconfig["public_key"]}', 'persistent-keepalive', '25')
    if ipv4only:
        nmconfig.set(f'wireguard-peer.{warpconfig["public_key"]}', 'allowed-ips', '0.0.0.0/0')
    else:
        nmconfig.set(f'wireguard-peer.{warpconfig["public_key"]}', 'allowed-ips', '0.0.0.0/0, ::/0')
    nmconfig.set('ipv4', 'address1', f'{warpconfig["interface"]["v4"]}/32')
    nmconfig.set('ipv4', 'dns', '1.1.1.1')
    nmconfig.set('ipv4', 'method', 'manual')
    if dnssearch:
        LOG.info('adding following domains search in ipv4 section: %s',
                 dnssearch)
        nmconfig.set('ipv4', 'dns-search', ';'.join(dnssearch.split()) + ';')
    for number in range(0, len(routes4)):
        nmconfig.set('ipv4', f'route{number+1}', routes4[number])
    if ipv4only:
        LOG.info('disabling ipv6 in networkmanager wireguard connection configuration')
        nmconfig.set('ipv6', 'addr-gen-mode', 'stable-privacy')
        nmconfig.set('ipv6', 'method', 'disabled')
    else:
        LOG.info('enabling ipv6 in networkmanager wireguard connection configuration')
        nmconfig.set('ipv6', 'addr-gen-mode', 'eui64')
        nmconfig.set('ipv6', 'address1', f'{warpconfig["interface"]["v6"]}/128')
        nmconfig.set('ipv6', 'dns', '2606:4700:4700::1111')
        if dnssearch:
            LOG.info('adding following domains search in ipv6 section: %s',
                     dnssearch)
            nmconfig.set('ipv6', 'dns-search', ';'.join(dnssearch.split()) + ';')
        nmconfig.set('ipv6', 'method', 'manual')
        for number in range(0, len(routes6)):
            nmconfig.set('ipv6', f'route{number+1}', routes6[number])
    return nmconfig

def deploy_nm_config(nmconfig, nmname, nmpath, overwrite, nmreload, dry_run):
    '''
    deploy networkmanager configuration
    '''
    msg = 'unknown status'
    write = False
    if nmpath.endswith('/'):
        nmpath = nmpath[:-1]
    config_file = f'{nmpath}/{nmname}.nmconnection'
    if os.path.isfile(config_file) and not overwrite:
        msg = 'file exists, skipping write'
    elif os.path.isfile(config_file) and overwrite:
        msg = 'file exists, overwriting'
        write = True
    elif not os.path.isfile(config_file):
        msg = 'file does not exists, creating'
        write = True
    LOG.info('%s: %s',
             msg, config_file)
    if write and dry_run:
        LOG.info('would have create/overwrite file: %s',
                 config_file)
    elif not write and dry_run:
        LOG.info('would have skip creating/overwriting file: %s',
                 config_file)
    elif write and not dry_run:
        try:
            with open(config_file, 'w', encoding='utf8') as nmconnfile:
                nmconfig.write(nmconnfile)
        except PermissionError as perms_ex:
            LOG.info('can not write file, insufficient permissions: %s',
                     config_file)
            LOG.debug('exception message: %s',
                      perms_ex)
            raise IOError from perms_ex
        LOG.info('setting permissions to 600: %s',
                 config_file)
        os.chmod(config_file, 0o600)
        if nmreload:
            LOG.info('reloading networkmanager configuration')
            shell_command('nmcli c reload')


def main():
    '''
    do all the things
    '''
    args = parse_args()
    configure_logging(args.debug, args.dry_run)
    try:
        warpconfig = read_json(args.warpconfig)
        wgconfig = read_json(args.wgconfig)
    except IOError:
        return 1
    try:
        nmconfig = create_nm_config(warpconfig, wgconfig, args.interface, args.nmconnectionname, args.ipv4only, args.domainsearch)
    except KeyError as warpconf_ex:
        LOG.error('missing parts in cloudflare warp configuration: %s',
                  warpconf_ex)
        return 1
    try:
        deploy_nm_config(nmconfig, args.nmconnectionname, args.nmconnectionpath, args.overwrite, args.nmreload, args.dry_run)
    except IOError:
        return 1
    return 0

if __name__ == '__main__':
    exit(main())
