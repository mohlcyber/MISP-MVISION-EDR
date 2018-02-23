#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import json

from pymisp import PyMISP
from mar import action

def init(url, key):
    return PyMISP(url, key, False, 'json', debug=False)

def search(tag):
    res = misp.search(
        tags=tag
    )
    return res

def lookup(data, eventid, euuid, ntag):
    auuid = data['uuid']
    md5 = data['value']
    print 'MD5 Hash found %s in an Event with the ID %s.' % (md5, str(eventid))
    print 'Looking for Hosts with this Hash.'
    res = action(md5)
    if not res:
        print 'No System found with this Hash.'
        pass
    else:
        total = res['totalItems']
        print 'Found %s Host(s) with that Hash.' % str(total)

        comment = []
        for item in res['items']:
            hostname = item['output']['HostInfo|hostname']
            ip = item['output']['HostInfo|ip_address']
            status = item['output']['Files|status']
            print 'Hostname: %s    |    IP: %s    |    Status: %s' % (hostname, ip, status)
            found = '%s | %s | %s' % (hostname, ip, status)
            comment.append(found)

            # Generate new attributes in the same event
            event = misp.get_event(eventid)
            target = misp.add_target_machine(event,
                                             found,
                                             category='Targeting data',
                                             to_ids=True,
                                             comment=None,
                                             distribution=None)

        # Generate new comment to the attribute
        comment = json.dumps(comment)
        comment = misp.change_comment(auuid, comment)

        a_tag = update_tag(auuid, ntag)
        e_tag = update_tag(euuid, ntag)
        sighting = misp.sighting_per_uuid(auuid)

def update_tag(uuid, ntag):
    res = misp.tag(uuid, ntag)
    return res


if __name__ == '__main__':

    tag = "hunting"
    ntag = "Indicator_Found"
    url = "https://localhost/"
    key = "access key"

    misp = init(url, key)
    misp_result = search(tag)
    i = 0

    try:
        for event in misp_result['response']:
            i = i + 1
            eventid = event['Event']['id']
            euuid = event['Event']['uuid']

            print '-------------------------'
            objects = event['Event']['Object']
            for fields in objects:
                for attributes in fields['Attribute']:
                    type = attributes['type']
                    if type == 'md5':
                        lookup(attributes, eventid, euuid, ntag)
                    else:
                        pass

            attributes = event['Event']['Attribute']
            for fields in attributes:
                type = fields['type']
                if type == 'md5':
                    lookup(fields, eventid, euuid, ntag)
                else:
                    pass

            misp.untag(euuid, tag)

    except:
        print "Somthing went wrong"
