#!/usr/bin/python

import urllib, subprocess
import os

from canari.maltego.message import UIMessage
from canari.maltego.message import MaltegoException
from canari.maltego.entities import IPv4Address
from canari.framework import configure
from canari.config import config

__author__ = 'bostonlink'
__copyright__ = 'Copyright 2012, Netwitness Maltego Integration Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'bostonlink'
__email__ = 'bostonlink@pentest-labs.org'
__status__ = 'Development'

__all__ = [
    'dotransform'
]

@configure(
    label='Launch Netwitness - Windows Only [Netwitness]',
    description='Launches netwitness Investigator and queries the specified IP address',
    uuids=[ 'netwitness.v2.NetwitnessLaunchInvestigator_Netwitness' ],
    inputs=[ ( 'Netwitness', IPv4Address ) ],
    debug=False
)
def dotransform(request, response, config):
    ip_entity = request.value
    where_clause = 'ip.src=%s || ip.dst=%s' % (ip_entity, ip_entity)
    base_url = "nw://%s/?collection=%s&" % (config['netwitness/concentrator_ip'], config['netwitness/collection_name'])
    params_dic = {'name': "Maltego Query", 'where': where_clause}
    enc_uri = urllib.urlencode(params_dic)
    full_url = base_url + enc_uri
    nw_path = config['netwitness/nw_investigator']
    try:
        os.chdir(nw_path)
        subprocess.Popen(['NwInvestigator.exe', full_url], stdout=subprocess.PIPE, shell=False)
        response += UIMessage('Netwitness Investigator Launched on %s' % ip_entity)
        return response
    except Exception as e:
        raise MaltegoException("The Transform has returned: %s" % e)