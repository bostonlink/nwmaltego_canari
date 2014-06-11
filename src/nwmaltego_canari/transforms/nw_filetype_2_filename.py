#!/usr/bin/env python

import json
from datetime import datetime, timedelta
from common.entities import NWFilename, NWFiletype
from canari.framework import configure
from canari.config import config
from common import nwmodule

__author__ = 'bostonlink'
__copyright__ = 'Copyright 2013, Netwitness Maltego Integration Project'
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
    label='Filetype To Filename [Netwitness]',
    description='Returns file names associated with the specified file type from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessFiletypeToFileName_Netwitness' ],
    inputs=[ ( 'Netwitness', NWFiletype ) ],
    debug=True
)
def dotransform(request, response):

    nwmodule.nw_http_auth()

    # NW REST API Query and results

    file_type = request.value
    diff = nwmodule.nwtime(config['netwitness/days'])
    field_name = 'filename'
    where_clause = '(time=%s) && filetype="%s"' % (diff, file_type)

    json_data = json.loads(nwmodule.nwValue(0, 0, 25, field_name, 'application/json', where_clause))
    file_list = []

    for d in json_data['results']['fields']:
        if d['value'] not in file_list:
            response += NWFilename(
                d['value'].decode('ascii'),
                filetype=file_type,
                metaid1=d['id1'],
                metaid2=d['id2'],
                type_=d['type'],
                count=d['count']
            )
            file_list.append(d['value'])

    return response



