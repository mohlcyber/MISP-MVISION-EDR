#!/usr/bin/env python3
# Written by mohlcyber v.0.3 06/03/2020

import requests
import sys
import time

from pymisp import ExpandedPyMISP, MISPAttribute

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlmarclient import MarClient

requests.packages.urllib3.disable_warnings()

misp_url = 'https://1.1.1.1'
misp_key = 'api key'
misp_verify = False
misp_tag = 'McAfee: Run MVISION EDR Query'
misp_ntag = 'McAfee: MVISION EDR Indicator Found'

dxl_config = 'path to dxlclient.config'


class EDRMISP():

    def __init__(self):
        self.config = DxlClientConfig.create_dxl_config_from_file(dxl_config)
        self.misp = ExpandedPyMISP(misp_url, misp_key, misp_verify)
        self.tags = self.misp.tags()
        self.attributes = []
        self.found = False

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

    def edr_search(self, eventid, hash, attr_id, attr_uuid):
        hostnames = []

        with DxlClient(self.config) as client:
            client.connect()
            marclient = MarClient(client)

            results_context = \
                marclient.search(
                    projections=[{
                        "name": "HostInfo",
                        "outputs": ["hostname", "ip_address"]
                    }, {
                        "name": "Files",
                        "outputs": ["name", "md5", "status", "full_name"]
                    }],
                    conditions={
                        "or": [{
                            "and": [{
                                "name": "Files",
                                "output": "md5",
                                "op": "EQUALS",
                                "value": hash
                            }]
                        }]
                    }
                )

            if results_context.has_results:
                results = results_context.get_results()
                total = results['totalItems']
                print('SUCCESS: Found {0} Host(s) with hash {1}.'.format(str(total), hash))

                for item in results['items']:
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
                print('SUCCESS: No System found containing files with hash {0}'.format(hash))

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
                            self.edr_search(eventid, attributes['value'], attributes['id'], attributes['uuid'])

                    for objects in event['Event']['Object']:
                        for attributes in objects['Attribute']:
                            if attributes['type'] == 'md5':
                                print('STATUS: Found MD5 {0} in Event {1}. Trying to lookup Endpoint with MVISION EDR.'
                                      .format(str(attributes['value']), eventid))
                                self.edr_search(eventid, attributes['value'], attributes['id'], attributes['uuid'])

                    self.misp.untag(event['Event']['uuid'], misp_tag)

                    if self.found is True:
                        self.misp.tag(event['Event']['uuid'], misp_ntag)

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print('ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}'
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(error)))


if __name__ == '__main__':
    while True:
        misp = EDRMISP().main()
        time.sleep(30)
