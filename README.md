# MISP - McAfee Active Response integration
This Integration adds automated hunting capabilities to the MISP platform with McAfee Active Response.

Based on tagging a script will extract suspicious MD5 hashes from an Threat Event and will launch automated McAfee Active Response lookups. 
If indicators found within the enterprise the script will automatically retag the threat event, add sightings and comments with the findings.

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
Enter the MISP url and access key in the misp_mar.py file (line 67, 68).
Create a tag that the analyst uses to initiate the hunting process. (e.g. hunting).
Create a tag that will be assigned to event where indicators found. (e.g. Indicator_Found).
Enter the tags in the misp_mar.py file (line 65, 66).
```sh
if __name__ == '__main__':

  tag = "hunting"
  ntag = "Indicator_Found"
  url = "https://localhost/"
  key = "access key"
```
Create Certificates for OpenDXL and move them into the config folder ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/epoexternalcertissuance.html)). 

Make sure to authorized the new created certificates in ePO to use the McAfee Active Response API ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/marsendauth.html)).

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
