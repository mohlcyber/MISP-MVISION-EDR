import os
import sys

from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxlmarclient import MarClient, ResultConstants, ProjectionConstants, \
    ConditionConstants, SortConstants, OperatorConstants

def action(md5):
    CONFIG_FILE = "path to the config file"
    config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

    with DxlClient(config) as client:

        client.connect()
        marclient = MarClient(client)

        results_context = \
            marclient.search(
               projections=[{
                     "name": "HostInfo",
                     "outputs": ["hostname","ip_address"]
               }, {
                     "name": "Files",
                     "outputs": ["md5","status"]
               }],
               conditions={
                   "or": [{
                      "and": [{
                      "name": "Files",
                      "output": "md5",
                      "op": "EQUALS",
                      "value": md5
                      }]
                   }]
               }
            )

        if results_context.has_results:
            results = results_context.get_results()
            return results
        else:
            pass
