#!/usr/bin/env python

import json
from canari.maltego.entities import Phrase
from common.entities import NWMetakey
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
    label='Phrase To MetaKeys [Netwitness]',
    description='Returns meta of metakey within the specified phrase from Netwitness.',
    uuids=[ 'netwitness.v2.NetwitnessPhrasetoMeta_Netwitness' ],
    inputs=[ ( 'Netwitness', Phrase ) ],
    debug=False
)
def dotransform(request, response, config):

    # NW REST API Query and results

    phrase = request.value
    diff = nwmodule.nwtime(config['netwitness/days'])
    query = 'select %s where (time=%s) && %s exists' % (phrase, diff, phrase)

    json_data = json.loads(nwmodule.nwQuery(0, 0, query, 'application/json', 2500))
    meta_list = []

    for d in json_data['results']['fields']:
        count = 1
        for a in json_data['results']['fields']:
            if d['value'] == a['value']:
                count += 1

        if d['value'] not in meta_list:
            response += NWMetakey(
                d['value'].decode('ascii'),
                weight=count)

            meta_list.append(d['value'])

        count = 0

    return response
