#!/usr/bin/python

import sys, urllib, subprocess

from canari.maltego.message import MaltegoMessage
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
    debug=True
)

# Must test against a Windows system - Consider this function unstable at the moment.

def dotransform(request, response):

    ip_entity = request.value
    where_clause = 'ip.src=%s || ip.dst=%s' % (ip_entity, ip_entity)

    base_url = "nw://%s/?collection=%s&" % (config['concentrator_ip'], config['collection_name'])
    params_dic = {'name': "Maltego Query", 'where': where_clause}
    enc_uri = urllib.urlencode(params_dic)
    full_url = base_url + enc_uri
    nw_path = config['nw_investigator']

    subprocess.Popen([nw_path, full_url], stdout=subprocess.PIPE, shell=False)
    sys.exit(0)

    return MaltegoMessage("NW Investigator Launched and querying %s" % ip_entity)