# MISP - McAfee Active Response integration
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This Integration adds automated hunting capabilities to the MISP platform with McAfee Active Response.

Based on tagging a script will extract suspicious MD5 hashes from an threat event and will launch automated McAfee Active Response lookups. 
If indicators found within the enterprise the script will automatically retag the threat event, add sightings and comments with the findings.

<img width="889" alt="screen shot 2018-06-29 at 11 01 15" src="https://user-images.githubusercontent.com/25227268/42083667-db54a28c-7b8b-11e8-85d9-e1a4805a717c.png">

## Component Description
**MISP** threat sharing platform is a free and open source software helping information sharing of threat and cyber security indicators. https://github.com/MISP/MISP

**McAfee Active Response** is an endpoint detection and response solution. It provides the cability to query endpoint in real-time. https://www.mcafee.com/in/products/active-response.aspx

## Prerequisites
MISP platform ([Link](https://github.com/MISP/MISP)) (tested with MISP 2.4.86)

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

McAfee ePolicy Orchestrator, DXL Broker, Active Response

## Configuration
Enter the MISP url and access key in the misp_mar.py file (line 68, 69).

Create a tag that the analyst uses to initiate the hunting process. (e.g. investigate).

Create a tag that will be assigned to event where indicators found. (e.g. Indicator_Found).

Enter the tags in the misp_mar.py file (line 66, 67).
```sh
if __name__ == '__main__':

    tag = "investigate" #Enter the tag to search for
    ntag = "indicator_found" #Enter the new tag to assign when indicators found
    url = "https://misp-ip/" #Enter the MISP IP
    key = "api key" #Enter the MISP api key
    
```
Create Certificates for OpenDXL and move them into the config folder ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/epoexternalcertissuance.html)). 

Make sure to authorize the new created certificates in ePO to use the McAfee Active Response API ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/marsendauth.html)).

Make sure that the FULL PATH to the config file is entered in line 10 (mar.py).

### Optional

run the script as a cronjob

```sh
sudo crontab -e
```

enter at the bottom e.g.:
```sh
*/1 * * * * python /home/misp_mar/misp_mar.py > /home/misp_mar/output.log
```

This will run the script every minute and create an output file.

## Video

[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/4AkLaPFCdWY/0.jpg)](https://www.youtube.com/watch?v=4AkLaPFCdWY)

link: https://youtu.be/4AkLaPFCdWY

## Summary
MISP contains global, community and locally produced intelligence that can be used with McAfee Active Response for automated threat hunting.
