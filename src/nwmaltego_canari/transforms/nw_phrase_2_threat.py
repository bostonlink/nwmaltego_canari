#!/usr/bin/env python

import json
from canari.maltego.entities import Phrase
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
    label='Phrase To Threat [Netwitness]',
    description='Returns threats associated with the specified phrase from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessPhrasetoThreat_Netwitness' ],
    inputs=[ ( 'Netwitness', Phrase ) ],
    debug=False
)
def dotransform(request, response, config):

    # NW REST API Query and results

    phrase = request.value
    diff = nwmodule.nwtime(config['netwitness/days'])
    query = 'select risk.warning where (time=%s) && risk.warning contains %s' % (diff, phrase)

    json_data = json.loads(nwmodule.nwQuery(0, 0, query, 'application/json', 2500))
    threat_list = []

    for d in json_data['results']['fields']:
        if d['value'] not in threat_list:
            response += NWThreat(
                d['value'].decode('ascii'),
                metaid1=d['id1'],
                metaid2=d['id2'],
                type_=d['type'],
                count=d['count']
            )
            threat_list.append(d['value'])

    return response
