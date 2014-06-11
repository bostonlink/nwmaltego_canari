#!/usr/bin/env python

import json
from common.entities import NWThreat, NWUserAgent
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
    label='Threat To User-Agent [Netwitness]',
    description='Returns user-agents associated with the specified threat from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessThreattoUA_Netwitness' ],
    inputs=[ ( 'Netwitness', NWThreat ) ],
    debug=False
)
def dotransform(request, response, config):

    # NW REST API Query and results

    risk_name = request.value
    diff = nwmodule.nwtime(config['netwitness/days'])

    if 'ip' in request.fields:
        ip_entity = request.fields['ip']
        where_clause = '(time=%s) && risk.warning="%s" && ip.src=%s || ip.dst=%s' % (diff, risk_name, ip_entity, ip_entity)
    else:
        where_clause = '(time=%s) && risk.warning="%s"' % (diff, risk_name)

    field_name = 'client'
    json_data = json.loads(nwmodule.nwValue(0, 0, 10, field_name, 'application/json', where_clause))
    ip_list = []

    for d in json_data['results']['fields']:
        if d['value'] not in ip_list:
            response += NWUserAgent(
                d['value'].decode('ascii'),
                metaid1=d['id1'],
                metaid2=d['id2'],
                type_=d['type'],
                count=d['count']
            )
            ip_list.append(d['value'])

    return response
