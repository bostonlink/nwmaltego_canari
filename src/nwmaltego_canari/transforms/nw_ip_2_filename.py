#!/usr/bin/env python

import json

from canari.maltego.entities import IPv4Address
from common.entities import NWFilename
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
    label='IP To Filename [Netwitness]',
    description='Returns file names associated with the specified IP address from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessIPToFilename_Netwitness' ],
    inputs=[ ( 'Netwitness', IPv4Address ) ],
    debug=True
)

def dotransform(request, response):

    nwmodule.nw_http_auth()

    # NW REST API Query and results

    ip_entity = request.value

    field_name = 'filename'
    where_clause = 'ip.src=%s || ip.dst=%s' % (ip_entity, ip_entity)

    json_data = json.loads(nwmodule.nwValue(0, 0, 25, field_name, 'application/json', where_clause))
    file_list = []

    for d in json_data['results']['fields']:
        if d['value'] not in file_list:
            response += NWFilename(
                d['value'].decode('ascii'),
                ip=ip_entity,
                metaid1=d['id1'],
                metaid2=d['id2'],
                type_=d['type'],
                count=d['count']
            )
            file_list.append(d['value'])

    return response