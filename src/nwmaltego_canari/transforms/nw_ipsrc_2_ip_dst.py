#!/usr/bin/env python

import json
from datetime import datetime, timedelta

from canari.maltego.entities import IPv4Address
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
    label='IP To IP Destination [Netwitness]',
    description='Returns IP destination addresses associated with the specified IP source address from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessIPsrcToIPdst_Netwitness' ],
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

    query = 'select ip.dst where (time=%s) && ip.src=%s' % (diff, ip_entity)

    json_data = json.loads(nwmodule.nwQuery(0, 0, query, 'application/json', 10))
    ip_list = []

    for d in json_data['results']['fields']:
        if d['value'] not in ip_list:
            response += IPv4Address(d['value'].decode('ascii'))
            ip_list.append(d['value'])

    return response
