# MISP - McAfee MVISION EDR integration
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This integration adds automated hunting capabilities to the MISP platform with McAfee MVISION EDR.

Based on tagging a script will extract suspicious MD5 hashes from a threat event and will launch automated MVISION EDR lookups. 
If indicators found - the script will automatically re-tag the threat event, add sightings, add attributes and comments.

<img width="863" alt="Screenshot 2020-02-13 at 20 42 35" src="https://user-images.githubusercontent.com/25227268/74471958-6a661e80-4ea1-11ea-89f7-0c11356b2024.png">

## Component Description
**MISP** threat sharing platform is a free and open source software helping information sharing of threat and cyber security indicators. https://github.com/MISP/MISP

**McAfee MVISION EDR** is an endpoint detection and response solution. It provides the cability to query endpoint in real-time. https://www.mcafee.com/enterprise/en-us/products/mvision-edr.html

## Prerequisites
MISP platform ([Link](https://github.com/MISP/MISP)) (tested with MISP 2.4.121)

PyMISP ([Link](https://github.com/MISP/PyMISP))
```sh
git clone https://github.com/MISP/PyMISP.git
cd PyMISP/
python setup.py install
```

Requests ([Link](http://docs.python-requests.org/en/master/user/install/#install))

OpenDXL SDK ([Link](https://github.com/opendxl/opendxl-client-python))
```sh
git clone https://github.com/opendxl/opendxl-client-python.git
cd opendxl-client-python/
python setup.py install
```

OpenDXL MAR SDK ([Link](https://github.com/opendxl/opendxl-mar-client-python))
```sh
git clone https://github.com/opendxl/opendxl-mar-client-python.git
cd opendxl-mar-client-python/
python setup.py install
```

On-Prem McAfee ePolicy Orchestrator, DXL Broker, MVISION EDR.

## Configuration
Enter the MISP url and access key in the misp_edr.py file (line 16, 17).

Create a tag that the analyst uses to initiate the hunting process. (e.g. McAfee: Run MVISION EDR Query).

Create a tag that will be assigned to event where indicators found. (e.g. McAfee: MVISION EDR Indicator Found).

Modify the misp_edr.py file (line 16 - 22).
```sh
misp_url = 'https://1.1.1.1'
misp_key = 'api key'
misp_verify = False
misp_tag = 'McAfee: Run MVISION EDR Query'
misp_ntag = 'McAfee: MVISION EDR Indicator Found'

dxl_config = '/path/to/dxlclient.config'
```
Create Certificates for OpenDXL and move them into the config folder ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/epoexternalcertissuance.html)). 

Make sure to authorize the new created certificates in ePO to use the McAfee Active Response API ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/marsendauth.html)).

Make sure that the FULL PATH to the config file is entered in line 22.

## Video

[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/C68cJ9XnjbI/0.jpg)](https://youtu.be/C68cJ9XnjbI)

link: https://youtu.be/C68cJ9XnjbI

## Summary
MISP contains global, community and locally produced intelligence that can be used with McAfee MVISION EDR for automated threat hunting.
