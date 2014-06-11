#!/usr/bin/env python
# Copyright (C) 2012 nwmaltego Developer.
# This file is part of nwmaltego - https://github.com/bostonlink/nwmaltego
# See the file 'LICENSE' for copying permission.

# Author: David Bressler
# Netwitness python functions to interface with the NW REST API

import urllib
import requests
import os
import ssl

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from datetime import datetime, timedelta
from canari.config import config
from canari.easygui import multpasswordbox
from canari.utils.fs import cookie, fsemaphore
from canari.maltego.message import MaltegoException

def get_creds():
    fn = cookie('netwitness')
    if not os.path.exists(fn):
        with fsemaphore(fn, 'wb') as f:
            f.lockex()
            while True:
                msg = 'Please enter your Netwitness credentials'
                fv = multpasswordbox(msg, 'Netwitness Credentials', ['Username:', 'Password:']) 
                if not fv:
                    f.close()
                    os.unlink(fn)
                    return

                nwu, nwp = fv
                f.write('username=%s#password=%s' % (nwu, nwp))
                break

    else:
        with fsemaphore(fn) as f:
            f.locksh()
            creds = f.read().split('#')
            for i in creds:
                if 'username' in i:
                    parse = i.split('=')
                    nwu = parse[1]
                if 'password' in i:
                    parse = i.split('=')
                    nwp = parse[1]

    return nwu, nwp


class TLSv1HttpAdapter(HTTPAdapter):
    """"Transport adapter" that allows us to use TLSv1."""

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1)


def get_http(full_url, nwu, nwpass):
    try:
        s = requests.Session()
        s.mount('https://', TLSv1HttpAdapter())
        s.auth = (nwu, nwpass)
        s.headers.update({'WWW-Authenticate': 'Basic realm="Netwitness"'})
        r = s.get(full_url, verify=False)
        return r.content
    except Exception as e:
        raise MaltegoException("The Transform has returned: %s" % e)

# function that adds date and time to queries

def nwtime(days):
    date_t = datetime.today()
    tdelta = timedelta(days=days)
    diff = date_t - tdelta
    diff = "'" + diff.strftime('%Y-%b-%d %H:%M:%S') + "'-'" + date_t.strftime('%Y-%b-%d %H:%M:%S') + "'"
    return diff

# Sample query examples that can be passed to the nwQuery module
# query = 'select service,ip.src,country.dst where service=80'
# pe_java_query = 'select filename,ip.src,ip.dst where filetype="x86 pe","java_jar"'
# all_pe_query = 'select filename,ip.src,ip.dst where filetype="x86 pe"'
# ip_exe_query = 'select filename,ip.src,ip.dst where filetype="x86 pe","java_jar" && (ip.src=1.1.1.1)'

def nwQuery(id1, id2, query_string, cType, size):

    """ Queries the NW REST API and returns the results 
    Example query that would be passed to the function in the query_string variable:
    query = 'select service,ip.src,country.dst where service=80'"""

    nwa = config['netwitness/nw_concentrator']

    base_uri = "/sdk?msg=query&"
    params_dic = {'force-content-type': cType, 'expiry': 600, 'id1': id1, 'id2': id2, 'size': size,
                  'query': query_string}

    enc_params = urllib.urlencode(params_dic)
    full_url = nwa + base_uri + enc_params
    nwu, nwp = get_creds()

    return get_http(full_url, nwu, nwp)

#  Retrieves the meta id range for the session range

def nwSession(id1, id2, cType):

    """ Returns the meta id for a specific session range.  
    If id1=0 and id2=0 it returns the meta id range for all data """

    nwa = config['netwitness/nw_concentrator']

    base_uri = "/sdk?msg=session&"
    params_dic = {'force-content-type': cType, 'expiry': 600, 'id1': id1, 'id2': id2}

    enc_params = urllib.urlencode(params_dic)
    full_url = nwa + base_uri + enc_params
    nwu, nwp = get_creds()

    return get_http(full_url, nwu, nwp)

# values: Performs a query and returns the matching values for a report
# example: nwValue(nwa, 0, 0, 100, 'risk.warning', 'text/plain')

def nwValue(id1, id2, size, fieldname, cType, where=''):

    """ Returns a values associated with a meta type.
    If the where_clause is used, you can return specific values of a certain type.
    For example:

    nwmodule.nwValue(nwa, 0, 0, 100, 'risk.warning', 'text/plain')

    returns all values associated with the risk.warning meta type."""

    nwa = config['netwitness/nw_concentrator']
    base_uri = "/sdk?msg=values&"
    params_dic = {'force-content-type': cType, 'expiry': 600, 'id1': id1, 'id2': id2, 'size': size,
                  'fieldName': fieldname, 'where': where}

    enc_params = urllib.urlencode(params_dic)
    full_url = nwa + base_uri + enc_params
    nwu, nwp = get_creds()

    return get_http(full_url, nwu, nwp)


# timeline: Returns the count of sessions/size/packets in discrete time intervals
# example: 

def nwTimeline(time1, time2, size, cType, where=''):

    """ Returns the count of sessions/size/packets in discrete time intervals """

    nwa = config['netwitness/nw_concentrator']
    base_uri = "/sdk?msg=timeline&"
    params_dic = {'force-content-type': cType, 'expiry': 600, 'time1': time1, 'time2': time2, 'size': size,
                  'where': where}

    enc_params = urllib.urlencode(params_dic)
    full_url = nwa + base_uri + enc_params
    nwu, nwp = get_creds()

    return get_http(full_url, nwu, nwp)


# Returns all queryable fields and definitions wtihin NW

def nwLanguage(cType):

    """ Returns all field types and definitions you can query wtihin NW """

    nwa = config['netwitness/nw_concentrator']
    base_uri = "/sdk?msg=language&"
    params_dic = {'force-content-type': cType, 'expiry': 600, 'size': 200}

    enc_params = urllib.urlencode(params_dic)
    full_url = nwa + base_uri + enc_params
    nwu, nwp = get_creds()

    return get_http(full_url, nwu, nwp)
