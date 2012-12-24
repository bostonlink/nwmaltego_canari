#!/usr/bin/env python

from canari.maltego.entities import EntityField, Entity


@EntityField(name='metaid1', propname='metaid1', displayname='Meta ID 1')
@EntityField(name='metaid2', propname='metaid2', displayname='Meta ID 2')
@EntityField(name='type', propname='type_', displayname='Type')
@EntityField(name='count', propname='count', displayname='Count')
class NetwitnessEntity(Entity):
    namespace = 'netwitness'


@EntityField(name='filetype', propname='filetype', displayname='File Type')
@EntityField(name='risk_name', propname='riskname', displayname='Risk Name')
class NWFilename(NetwitnessEntity):
    pass


@EntityField(name='ip', propname='ip', displayname='IP Address')
@EntityField(name='risk_name', propname='riskname', displayname='Risk Name')
class NWFiletype(NetwitnessEntity):
    pass


class NWUserAgent(NetwitnessEntity):
    pass


@EntityField(name='ip', propname='ip', displayname='IP Address')
class NWThreat(NetwitnessEntity):
    pass


