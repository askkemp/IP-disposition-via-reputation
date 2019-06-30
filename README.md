

## Introduction
tl;dr: make a disposition based on IP Traits + Noise + Merchant Fraud + Sanitation and some other stuff. 

This script uses credit card fraud and other data to make a disposition (allow or block) about an IP address with the overall goal of determining the reputation of IP address. What makes this different that most reputation checks is that it is mostly based on merchant fruad. MaxMind and FraudLabs Pro offer credit card fraud detection services for merchants at an affordable cost. For each, feed it information about the transaction (e.g. username, IP address, email address, etc.) and it provides back various risk score information and IP characteristics. GreyNoise is a free collection of data that collects information on scanners (e.g. legit scanners), worms, attackers, etc. Shodan is a low cost tool that provides scan data about an IP. 

The below diagram is the overall concept. Take various pieces of reputation information for the IP, take into consideration how your network sees it (direction/service) and make a disposition. Directionality and service is important thus the disposition concept in this script is divided into three categories: web, vpn, email. And divided into two directionalities: in, out. 

```
  IP traits       # IP assigned to device in datacenter
+ Noise           # IP seen as SSH scanner
+ Merchant Fraud  # IP given medium risk
+ Sanitation      # IP is running vulnerable Apache
+ directionality  # Inbound to my network
+ service         # Connected to my network as VPN service

= Block inbound VPN connection!
```


## Help output

``` bash
python check_ip.py  --help
usage: check_ip.py [-h] [-MaxMindGeoIPInsights] [-MaxmindMinfraudIPscore]
                   [-maxmindemailscore MAXMINDEMAILSCORE] [-fraudlabsproip]
                   [-grey] [-shodan] -ipAddr IPADDR [-converttocsv]
                   [-doAllChecks]

Input an IP address and choose and API to run it against. Output will be JSON
with raw, currated, voting, and dispotion parent keys. Tool is used to
determine if an IP should be blocked or allowed if traffic is inbound or
outbound for VPN, WEB, and EMAIL.

optional arguments:
  -h, --help            show this help message and exit
  -MaxMindGeoIPInsights
                        Provides ip traits from Maxmind Geoip Insights.
  -MaxmindMinfraudIPscore
                        Provides risk score from Maxmind Minfraud service.
  -fraudlabsproip       Risk score from FraudLabs Pro service.
  -grey                 Scanner data from GreyNoise API
  -shodan               Enumeration data from Shodan host API
  -ipAddr IPADDR        Input: Single IP address used for next argument
  -converttocsv         Return CSV disposition
  -doAllChecks          Run all APIs
```

## Output
For each API querried the below JSON output is created. The `raw` key is all data as it came from the API. The `currated` key is only the data from the API that is useful for the disposition. The `recommendation` is a count of all characteristics seen for the API which is then later used in for the final decision seen in the `disposition` key.

``` json
{
  "disposition": {
    "inbound": {
    },
    "outbound": {
    }
  },
  "raw": {
  },
  "curated": {
  },
  "module": "Name of module",
  "recommendation": {
    "inbound": {
    },
    "outbound": {
    }
  }
}
```

The data can also be shown just as a CSV and the dispositon for each service.
```bash
python check_ip.py  -ipAddr  xxx.xxx.xxx.xxx  -doAllChecks  -converttocsv
xxx.xxx.xxx.xxx,MaxMindGeoIPInsights,True,True,True,True,True,True
xxx.xxx.xxx.xxx,GreyNoise,None,None,None,None,None,None
xxx.xxx.xxx.xxx,FraudLabsPro,True,True,True,True,True,True
xxx.xxx.xxx.xxx,MaxmindMinfraudIPscore,True,True,True,True,True,True
xxx.xxx.xxx.xxx,Shodan,None,None,None,None,None,None
```

## Requirements
* Python2.7
* Library geoip2 - https://pypi.org/project/geoip2/
* Library shodan - https://pypi.org/project/shodan/
* API key for Maxmind IP Insights - https://www.maxmind.com/en/geoip2-precision-insights
* API key for Maxmind MinFraud - https://www.maxmind.com/en/solutions/minfraud-services
* API key for Fraud Labs Pro - https://www.fraudlabspro.com/pricing
* API key for Shodan - https://developer.shodan.io/pricing (a developer level key will work)



## Example 1 - Check of a TOR exit node
Based on Maxmind Geoip Insights, Shodan, and Fruad Labs Pro data, the dispostion for al directionality and services is block.

``` json
$ python check_ip.py  -ipAddr 104.xxx.xxx.xxx -MaxMindGeoIPInsights| jq -c '[.module,.disposition]' | jq .
[
  "Maxmind Geoip Insights",
  {
    "inbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    },
    "outbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    }
  }
]
[
  "Fraud Labs Pro",
  {
    "inbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    },
    "outbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    }
  }
]
[
  "Maxmind Minfraud",
  {
    "inbound": {
      "Block_Email": false,
      "Block_VPN": false,
      "Block_Web": false
    },
    "outbound": {
      "Block_Email": false,
      "Block_VPN": false,
      "Block_Web": false
    }
  }
]
[
  "shodan",
  {
    "inbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    },
    "outbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    }
  }
]
```

## Example 2 - Check of a IP serving malware over HTTP
Via Fraud Labs Pro and shodan data, the disposition is to block all services in all directions. Via Maxmind Geoip Insights, the disposition is to only block inbound VPN.

``` json
$ python check_ip.py  -ipAddr xxx.xxx.xxx.xxx -doAllChecks   | jq -c '[.module,.disposition]' | jq .
[
  "Maxmind Geoip Insights",
  {
    "inbound": {
      "Block_Email": false,
      "Block_VPN": true,
      "Block_Web": false
    },
    "outbound": {
      "Block_Email": false,
      "Block_VPN": false,
      "Block_Web": false
    }
  }
]
[
  "Fraud Labs Pro",
  {
    "inbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    },
    "outbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    }
  }
]
[
  "Maxmind Minfraud",
  {
    "inbound": {
      "Block_Email": false,
      "Block_VPN": false,
      "Block_Web": false
    },
    "outbound": {
      "Block_Email": false,
      "Block_VPN": false,
      "Block_Web": false
    }
  }
]
[
  "shodan",
  {
    "inbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    },
    "outbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    }
  }
]

```


## Example 3 - Check of known spam mailer IP

```json
$ python check_ip.py  -ipAddr  xxx.xxx.xxx.xxx  -doAllChecks   | jq -c '[.module,.disposition]' | jq .
[
  "Maxmind Geoip Insights",
  {
    "inbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    },
    "outbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    }
  }
]
[
  "Fraud Labs Pro",
  {
    "inbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    },
    "outbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    }
  }
]
[
  "Maxmind Minfraud",
  {
    "inbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    },
    "outbound": {
      "Block_Email": true,
      "Block_VPN": true,
      "Block_Web": true
    }
  }
]
```


## Observations
Merchant fraud data is really good at labeling suspicious IPs. However, it appears that when an IP is flagged as suspicious, it slowly goes back to "normal" which means that sometimes an IP labeled as "suspicious" was at one point doing bad things, but might not anymore.

IP traits like if the IP is a server in a data center, or a TOR exit node, etc is useful and Maxmind appears to have very accurate data. It does appear that some of the merchant fruad data is using the traits of the IP (e.g. IP is in a data center) in their risk score calculation. 

Vulnerability data collected from Shodan is very interesting. But note that this is passively collected and by no means a system is actually vulnerable. 
