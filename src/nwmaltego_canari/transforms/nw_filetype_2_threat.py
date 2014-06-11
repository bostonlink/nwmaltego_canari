#!/usr/bin/env python

import json
from canari.maltego.entities import Phrase
from common.entities import NWThreat, NWFiletype
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
    label='Filetype To Threat [Netwitness]',
    description='Returns threats associated with the specified file type from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessFileTypeToThreat_Netwitness', 'netwitness.v2.NetwitnessFileTypePhraseToThreat_Netwitness' ],
    inputs=[ ( 'Netwitness', NWFiletype ), ('Netwitness', Phrase) ],
    debug=True
)
def dotransform(request, response, config):

    # NW REST API Query amd results

    file_type = request.value
    diff = nwmodule.nwtime(config['netwitness/days'])
    field_name = 'risk.warning'
    where_clause = '(time=%s) && filetype="%s"' % (diff, file_type)

    json_data = json.loads(nwmodule.nwValue(0, 0, 25, field_name, 'application/json', where_clause))
    threat_list = []

    for d in json_data['results']['fields']:
        if d['value'] not in threat_list:
            response += NWThreat(
                d['value'].decode('ascii'),
                filetype=file_type,
                metaid1=d['id1'],
                metaid2=d['id2'],
                type_=d['type'],
                count=d['count']
            )
            threat_list.append(d['value'])

    return response