#!/usr/bin/env python

import json
from canari.maltego.entities import Domain, IPv4Address
from canari.framework import configure
from canari.config import config
from common import nwmodule

__author__ = 'bostonlink'
__copyright__ = 'Copyright 2014, Netwitness Maltego Integration Project'
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
    label='Hostname Alias To IP destination [Netwitness]',
    description='Returns IP destination addresses associated with the alias.host from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessHostnameToIPdst_Netwitness' ],
    inputs=[ ( 'Netwitness', Domain ) ],
    debug=False
)
def dotransform(request, response, config):

    # NW REST API Query and results

    ip_entity = request.value
    diff = nwmodule.nwtime(config['netwitness/days'])
    query = 'select ip.dst where (time=%s) && alias.host=%s' % (diff, ip_entity)

    json_data = json.loads(nwmodule.nwQuery(0, 0, query, 'application/json', 2500))
    ip_list = []

    for d in json_data['results']['fields']:
        count = 1
        for a in json_data['results']['fields']:
            if d['value'] == a['value']:
                count += 1

        if d['value'] not in ip_list:
            response += IPv4Address(d['value'].decode('ascii'), weight=count)
            ip_list.append(d['value'])

        count = 0

    return response
