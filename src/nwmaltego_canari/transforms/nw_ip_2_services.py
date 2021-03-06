#!/usr/bin/env python

import json
from canari.maltego.message import Field
from canari.maltego.entities import IPv4Address, Service
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
    label='IP To Services [Netwitness]',
    description='Returns services associated with the specified IP address from Netwitness.',
    uuids=['netwitness.v2.NetwitnessIPToServices_Netwitness'],
    inputs=[('Netwitness', IPv4Address)],
    debug=False
)
def dotransform(request, response, config):

    # NW REST API Query and results

    ip_entity = request.value
    diff = nwmodule.nwtime(config['netwitness/days'])
    query = 'select service where (time=%s) && (ip.dst=%s || ip.src=%s)' % (diff, ip_entity, ip_entity)
    json_data = json.loads(nwmodule.nwQuery(0, 0, query, 'application/json', 2500))
    service_list = []

    for d in json_data['results']['fields']:
        count = 1
        for a in json_data['results']['fields']:
            if d['value'] == a['value']:
                count += 1

        if d['value'] not in service_list:
            e = Service(d['value'].decode('ascii'), weight=count)
            e += Field("ip", ip_entity, displayname='IP Address')
            response += e
            service_list.append(d['value'])

        count = 0

    return response
