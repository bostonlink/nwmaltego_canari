#!/usr/bin/env python

import json
from datetime import datetime, timedelta

from canari.maltego.entities import IPv4Address
from common.entities import NWUserAgent
from canari.framework import configure
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
    label='IP To User-Agent [Netwitness]',
    description='Returns user-agents associated with the specified IP address from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessIPToUA_Netwitness' ],
    inputs=[ ( 'Netwitness', IPv4Address ) ],
    debug=False
)

def dotransform(request, response):

    nwmodule.nw_http_auth()

    # NW REST API Query and results

    ip_entity = request.value

    date_t = datetime.today()
    tdelta = timedelta(days=1)
    diff = date_t - tdelta
    diff = "'" + diff.strftime('%Y-%b-%d %H:%M:%S') + "'-'" + date_t.strftime('%Y-%b-%d %H:%M:%S') + "'"

    field_name = 'client'
    where_clause = '(time=%s) && ip.src=%s || ip.dst=%s' % (diff, ip_entity, ip_entity)

    json_data = json.loads(nwmodule.nwValue(0, 0, 25, field_name, 'application/json', where_clause))
    ua_list = []

    for d in json_data['results']['fields']:
        if d['value'] not in ua_list:
            response += NWUserAgent(
                d['value'].decode('ascii'),
                ip=ip_entity,
                metaid1=d['id1'],
                metaid2=d['id2'],
                type_=d['type'],
                count=d['count']
            )
            ua_list.append(d['value'])

    return response