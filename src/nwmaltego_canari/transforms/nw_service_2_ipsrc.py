#!/usr/bin/env python

import json
from canari.maltego.message import Field
from canari.maltego.entities import Service
from common.entities import NWAction
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
    label='From Service to IP Src [Netwitness]',
    description='Returns IP Src associated with Service from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessServiceToIPSrc_Netwitness' ],
    inputs=[ ( 'Netwitness', Service) ],
    debug=False
)
def dotransform(request, response, config):

    # NW REST API Query and results
    diff = nwmodule.nwtime(config['netwitness/days'])
    service = request.value

    if 'ip' in request.fields:
        ip = request.fields['ip']
        query = 'select ip.src where (time=%s) && service=%s && (ip.src=%s || ip.dst=%s)' % (diff, service, ip, ip)
    else:
        breadhost = request.fields['hostname']
        query = 'select ip.src where (time=%s) && service=%s && alias.host=%s' % (diff, service, breadhost)

    json_data = json.loads(nwmodule.nwQuery(0, 0, query, 'application/json', 2500))
    service_list = []

    for d in json_data['results']['fields']:
        count = 1
        for a in json_data['results']['fields']:
            if d['value'] == a['value']:
                count += 1

        if d['value'] not in service_list:
            e = NWAction(d['value'].decode('ascii'), weight=count)
            if 'ip' in request.fields:
                e += Field("ip", ip, displayname='IP Address')
            else:
                e += Field("hostname", breadhost, displayname='Hostname')

            e += Field("service", request.value, displayname='Service')
            response += e
            service_list.append(d['value'])

        count = 0

    return response
