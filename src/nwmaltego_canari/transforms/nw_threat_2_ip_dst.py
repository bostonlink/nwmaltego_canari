#!/usr/bin/env python

import json
from common.entities import NWThreat
from canari.maltego.entities import IPv4Address
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
    label='Threat To IP Destination [Netwitness]',
    description='Returns IP destination addresses associated with the specified threat from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessThreattoIPdst_Netwitness' ],
    inputs=[ ( 'Netwitness', NWThreat ) ],
    debug=False
)
def dotransform(request, response, config):

    # NW REST API Query and results

    risk_name = request.value
    diff = nwmodule.nwtime(config['netwitness/days'])

    if 'ip' in request.fields:
        ip = request.fields['ip']
        query = 'select ip.dst where (time=%s) && risk.warning="%s" && ip.src=%s' % (diff, risk_name, ip)
    else:
        query = 'select ip.dst where (time=%s) && risk.warning="%s"' % (diff, risk_name)

    json_data = json.loads(nwmodule.nwQuery(0, 0, query, 'application/json', 10))
    ip_list = []

    for d in json_data['results']['fields']:
        if d['value'] not in ip_list:
            response += IPv4Address(d['value'].decode('ascii'))
            ip_list.append(d['value'])

    return response