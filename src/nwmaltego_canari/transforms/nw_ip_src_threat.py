#!/usr/bin/env python

import json
from canari.maltego.entities import IPv4Address
from common.entities import NWThreat
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
    label='IP Source To Threat [Netwitness]',
    description='Returns threat associated with the specified source IP address from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessIPsrcToThreat_Netwitness' ],
    inputs=[ ( 'Netwitness', IPv4Address ) ],
    debug=False
)
def dotransform(request, response, config):

    # NW REST API Query and results

    ip_entity = request.value
    diff = nwmodule.nwtime(config['netwitness/days'])
    field_name = 'risk.warning'
    where_clause = '(time=%s) && ip.src=%s' % (diff, ip_entity)

    json_data = json.loads(nwmodule.nwValue(0, 0, 25, field_name, 'application/json', where_clause))
    threat_list = []

    for d in json_data['results']['fields']:
        if d['value'] not in threat_list:
            response += NWThreat(
                d['value'].decode('ascii'),
                ip=ip_entity,
                metaid1=d['id1'],
                metaid2=d['id2'],
                type_=d['type'],
                count=d['count']
            )
            threat_list.append(d['value'])

    return response
