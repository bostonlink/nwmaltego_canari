#!/usr/bin/env python

import json
from canari.maltego.entities import IPv4Address
from canari.framework import configure
from canari.config import config
from common import nwmodule

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
    label='IP Destination To IP Source [Netwitness]',
    description='Returns IP source addresses associated with the specified IP address from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessIPdstToIPsrc_Netwitness' ],
    inputs=[ ( 'Netwitness', IPv4Address ) ],
    debug=False
)

def dotransform(request, response):

    nwmodule.nw_http_auth()

    # NW REST API Query and results

    ip_entity = request.value
    diff = nwmodule.nwtime(config['netwitness/days'])
    query = 'select ip.src where (time=%s) && ip.dst=%s' % (diff, ip_entity)

    json_data = json.loads(nwmodule.nwQuery(0, 0, query, 'application/json', 10))
    ip_list = []

    for d in json_data['results']['fields']:
        if d['value'] not in ip_list:
            response += IPv4Address(d['value'].decode('ascii'))
            ip_list.append(d['value'])

    return response