#!/usr/bin/env python3
# Written by mohlcyber v.0.2 16/06/2021

import requests
import sys
import time
import logging
import getpass

from argparse import ArgumentParser, RawTextHelpFormatter
from pymisp import ExpandedPyMISP, MISPAttribute

requests.packages.urllib3.disable_warnings()

misp_url = 'https://1.1.1.1'
misp_key = ''
misp_verify = False
misp_tag = 'McAfee: Run MVISION EDR Query'
misp_ntag = 'McAfee: MVISION EDR Indicator Found'


class EDRMISP():

    def __init__(self):
        self.misp = ExpandedPyMISP(misp_url, misp_key, misp_verify)
        self.tags = self.misp.tags()
        self.attributes = []
        self.found = False
            
        if args.region == 'EU':
            self.edr = 'https://api.soc.eu-central-1.mcafee.com'
        elif args.region == 'US':
            self.edr = 'https://api.soc.mcafee.com'
        elif args.region == 'SY':
            self.edr = 'https://soc.ap-southeast-2.mcafee.com'

        self.verify = True
        self.session = requests.Session()

        user = args.user
        pw = args.password
        self.creds = (user, pw)

    def edr_auth(self):
        r = self.session.get(self.edr + '/identity/v1/login', auth=self.creds)
        res = r.json()

        if r.status_code == 200:
            token = res['AuthorizationToken']
            self.headers = {'Authorization': 'Bearer {}'.format(token)}
            print('AUTHENTICATION: Successfully authenticated.')
        else:
            print('ERROR: Something went wrong during the authentication')
            sys.exit()

    def edr_search(self, hash):
        payload = {
            "projections": [
                {
                    "name": "HostInfo",
                    "outputs": ["hostname", "ip_address"]
                }, {
                    "name": "Files",
                    "outputs": ["name", "md5", "status", "full_name"]
                }
            ],
            "condition": {
                "or": [{
                    "and": [{
                        "name": "Files",
                        "output": "md5",
                        "op": "EQUALS",
                        "value": str(hash)
                    }]
                }]
            }
        }

        res = self.session.post(self.edr + '/active-response/api/v1/searches',
                                headers=self.headers,
                                json=payload)
        if res.status_code == 200:
            queryId = res.json()['id']
            print('SEARCH: MVISION EDR search got started successfully')
        else:
            print('ERROR: Could not find the query ID.')
            sys.exit()

        return queryId

    def edr_status(self, queryId):
        status = False
        res = self.session.get(self.edr + '/active-response/api/v1/searches/{}/status'.format(str(queryId)),
                               headers=self.headers)
        if res.status_code == 200:
            if res.json()['status'] == 'FINISHED':
                status = True
            else:
                print('STATUS: Search still in process. Status: {}'.format(res.json()['status']))
        return status

    def edr_result(self, queryId, eventid, attr_id, attr_uuid):
        hostnames = []
        res = self.session.get(self.edr + '/active-response/api/v1/searches/{}/results'.format(str(queryId)),
                               headers=self.headers)
        if res.status_code == 200:
            if res.json()['items'] != []:
                total = res.json()['totalItems']
                print('SUCCESS: Found {0} Host(s) with this hash.'.format(str(total)))

                for item in res.json()['items']:
                    hostname = item['output']['HostInfo|hostname']
                    ip = item['output']['HostInfo|ip_address']
                    status = item['output']['Files|status']
                    full_name = item['output']['Files|full_name']
                    md5 = item['output']['Files|md5']
                    finding = 'Hostname: {0} | IP: {1} | Status: {2} | Location: {3} | MD5: {4}'\
                        .format(hostname, ip, status, full_name, md5)
                    hostnames.append(hostname)

                    self.found = True
                    self.add_sighting(attr_id, hostname)
                    self.add_attribute(eventid, finding)

                self.update_attribute(attr_id, hostnames, attr_uuid)
            else:
                print('SUCCESS: No System found containing files with hash.')
        else:
            print('ERROR: Something went wrong to retrieve the results.')
            sys.exit()

    def edr_run_search(self, eventid, hash, attr_id, attr_uuid):
        self.edr_auth()
        queryid = self.edr_search(hash)
        while self.edr_status(queryid) is False:
            time.sleep(10)
        self.edr_result(queryid, eventid, attr_id, attr_uuid)

    def add_attribute(self, eventid, finding):
        attr = {
            "value": finding,
            "type": "target-machine"
        }
        self.misp.add_attribute(eventid, attr)

    def update_attribute(self, attr_id, comment, attr_uuid):
        data = {
            "comment": str(comment)
        }
        self.misp.update_attribute(data, attr_id)
        self.misp.tag(attr_uuid, misp_ntag)

    def add_sighting(self, attr_id, hostname):
        sight = {
            "values": "MVISION EDR",
            "id": attr_id,
            "source": "Target: {0}".format(hostname)
        }
        self.misp.add_sighting(sight)

    def main(self):
        try:
            events = self.misp.search(tags=misp_tag)
            if events:
                for event in events:
                    eventid = str(event['Event']['id'])
                    for attributes in event['Event']['Attribute']:
                        if attributes['type'] == 'md5':
                            print('STATUS: Found MD5 {0} in Event {1}. Trying to lookup Endpoint with MVISION EDR.'
                                  .format(str(attributes['value']), eventid))

                            self.edr_run_search(eventid, attributes['value'], attributes['id'], attributes['uuid'])

                    for objects in event['Event']['Object']:
                        for attributes in objects['Attribute']:
                            if attributes['type'] == 'md5':
                                print('STATUS: Found MD5 {0} in Event {1}. Trying to lookup Endpoint with MVISION EDR.'
                                      .format(str(attributes['value']), eventid))
                                self.edr_run_search(eventid, attributes['value'], attributes['id'], attributes['uuid'])

                    self.misp.untag(event['Event']['uuid'], misp_tag)

                    if self.found is True:
                        self.misp.tag(event['Event']['uuid'], misp_ntag)

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print('ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}'
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(error)))


if __name__ == '__main__':
    usage = """python misp_edr.py -R <REGION> -U <USERNAME> """
    title = 'MISP - McAfee EDR Integration'
    parser = ArgumentParser(description=title, usage=usage, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--region', '-R',
                        required=True, type=str,
                        help='MVISION EDR Tenant Location', choices=['EU', 'US'])

    parser.add_argument('--user', '-U',
                        required=True, type=str,
                        help='MVISION EDR Username')

    parser.add_argument('--password', '-P',
                        required=False, type=str,
                        help='MVISION EDR Password')

    args = parser.parse_args()
    if not args.password:
        args.password = getpass.getpass(prompt='MVISION EDR Password:')

    print('STATUS: Starting the MISP - MVISION EDR Service.')
    while True:
        misp = EDRMISP().main()
        time.sleep(30)
