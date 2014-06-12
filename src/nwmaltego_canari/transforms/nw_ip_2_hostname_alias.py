#!/usr/bin/env python

import json
from canari.maltego.entities import IPv4Address, Domain
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
    label='IP To Hostname Alias [Netwitness]',
    description='Returns hostname alias associated with the specified IP address from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessIPToHostname_Netwitness' ],
    inputs=[ ( 'Netwitness', IPv4Address ) ],
    debug=False
)
def dotransform(request, response, config):

    # NW REST API Query and results

    ip_entity = request.value
    diff = nwmodule.nwtime(config['netwitness/days'])
    field_name = 'alias.host'
    where_clause = '(time=%s) && ip.src=%s || ip.dst=%s' % (diff, ip_entity, ip_entity)

    json_data = json.loads(nwmodule.nwValue(0, 0, 250, field_name, 'application/json', where_clause))
    host_list = []

    for d in json_data['results']['fields']:
        if d['value'] not in host_list:
            response += Domain(d['value'].decode('ascii'))

    return response