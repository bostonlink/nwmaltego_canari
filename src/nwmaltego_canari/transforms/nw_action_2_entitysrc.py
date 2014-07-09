#!/usr/bin/env python

import json
from canari.maltego.message import Field
from canari.maltego.entities import IPv4Address, Domain
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
    label='From Action to Source [Netwitness]',
    description='Returns Source Entity associated with Action from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessActionToEntitySrc_Netwitness' ],
    inputs=[ ( 'Netwitness', NWAction) ],
    debug=False
)
def dotransform(request, response, config):

    # NW REST API Query and results
    if 'ip' in request.fields:
        diff = nwmodule.nwtime(config['netwitness/days'])
        query = 'select ip.src where (time=%s) && service=%s && (ip.dst=%s || ip.src=%s)' % (diff, request.fields['service'],request.fields['ip'], request.fields['ip'])
        json_data = json.loads(nwmodule.nwQuery(0, 0, query, 'application/json', 2500))
        entity_list = []

        for d in json_data['results']['fields']:
            count = 1
            for a in json_data['results']['fields']:
                if d['value'] == a['value']:
                    count += 1

            if d['value'] not in entity_list:
                response += IPv4Address(d['value'], weight=count)
                entity_list.append(request.fields['ip'])

    elif 'hostname' in request.fields:
        diff = nwmodule.nwtime(config['netwitness/days'])
        query = 'select ip.src where (time=%s) && service=%s && alias.host=%s' % (diff, request.fields['service'], request.fields['hostname'])
        json_data = json.loads(nwmodule.nwQuery(0, 0, query, 'application/json', 2500))
        entity_list = []

        for d in json_data['results']['fields']:
            count = 1
            for a in json_data['results']['fields']:
                if d['value'] == a['value']:
                    count += 1

            if d['value'] not in entity_list:
                response += IPv4Address(d['value'], weight=count)
                entity_list.append(request.fields['hostname'])

    return response
