# Make a disposition based on IP Traits + Noise + Merchant Fraud + Sanitation and some other stuff. 
# Copyright (C) 2018 Kemp Langhorne
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.


#
# CHANGE BELOW CONFIGURATION
#

# Maxmind Config - will work for IP Insights and MinFraud
userId = 12345 # should be int
apiKey = "abc"

# Fraud Labs Pro key
FraudLabsapiKey = "abc"

# Shodan API key
SHODAN_API_KEY = "abc"


# Imports
import json
import argparse
import requests
from datetime import datetime
from datetime import date
from datetime import timedelta
from dateutil.parser import parse
import pytz
import geoip2.webservice # maxmind
import shodan

#
# Parser for command-line options
#
parser = argparse.ArgumentParser(description='Input an IP address and choose and API to run it against. Output will be JSON with raw, currated, voting, and dispotion parent keys. Tool is used to determine if an IP should be blocked or allowed if traffic is inbound or outbound for VPN, WEB, and EMAIL.')
parser.add_argument('-MaxMindGeoIPInsights',
                    action='store_true', dest='MaxMindGeoIPInsights', required=False,
                    help='Provides ip traits from Maxmind Geoip Insights.')
parser.add_argument('-MaxmindMinfraudIPscore',
                    action='store_true', dest='MaxmindMinfraudIPscore', required=False,
                    help='Provides risk score from Maxmind Minfraud service.')
parser.add_argument('-fraudlabsproip',
                    action='store_true', dest='fraudlabsproip', required=False,
                    help='Risk score from FraudLabs Pro service.')
parser.add_argument('-grey',
                    action='store_true', dest='grey', required=False,
                    help='Scanner data from GreyNoise API')
parser.add_argument('-shodan',
                    action='store_true', dest='shodan', required=False,
                    help='Enumeration data from Shodan host API')
parser.add_argument('-ipAddr',
                    action='store', dest='ipAddr', required=True,
                    help='Input: Single IP address used for next argument')
parser.add_argument('-converttocsv',
                    action='store_true', dest='converttocsv', required=False,
                    help='Return CSV disposition')
parser.add_argument('-doAllChecks',
                    action='store_true', dest='doAllChecks', required=False,
                    help='Run all APIs')
args = parser.parse_args()



#
# API HTTPS Request
#
def maxmind_api_request(url,payload):
    '''
    Purpose: Perform HTTP POST to retrieve data from API
    Input: url of API as str and payload as JSON str
    Returns: response text or error str
    '''
    response = requests.post(
                url,
                data=payload,
                auth=(userId, apiKey),
                headers={
                    'Accept': 'application/json'
                },
                timeout=None)
    if response.status_code != 200:
        return "ERROR. Not HTTP 200. %s" % payload
    else:
        return response.text

def fraudlabspro_api_request(url,payload):
    '''
    Purpose: Perform HTTP POST to retrieve data from API
    Input: url of API as str and payload as JSON str
    Returns: response text or error str
    '''
    response = requests.post(
                url,
                data=payload,
                timeout=None)
    if response.status_code != 200:
        return "ERROR. Not HTTP 200. %s" % payload
    elif 'INVALID API KEY' in response.text:
        return "INVALID API KEY. %s" % payload
    else:
        return response.text

#
# To simplify repeating parts of various data pulls
#

def doDisposition(inputList):
    ''' 
        Purpose: Based on which state is higher than the other, set Block or Allow to True or False.
        Input: List of Block and Allow states. e.g. ['Allow_VPN', 'Allow_Email', 'Allow_Web']
        Output: dict                           e.g. {'Block_Email': False, 'Block_VPN': False, 'Block_Web': False}
    '''
    dispositionsList = inputList
    finalDisposition = {}

    # Set everything to allow before checking
    finalDisposition['Block_VPN'] = False
    finalDisposition['Block_Email'] = False
    finalDisposition['Block_Web'] = False
    
    # Majority rules. Probablty a bad idea... *ASCII shrug
    # Decided to be more burtal and just block if there is any block count
    #if dispositionsList.count("Block_VPN") > dispositionsList.count("Allow_VPN"):
    if dispositionsList.count("Block_VPN") > 0:
        finalDisposition['Block_VPN'] = True
    #if dispositionsList.count("Block_Email") > dispositionsList.count("Allow_Email"):
    if dispositionsList.count("Block_Email") > 0:
        finalDisposition['Block_Email'] = True
    #if dispositionsList.count("Block_Web") > dispositionsList.count("Allow_Web"):
    if dispositionsList.count("Block_Web") > 0:
        finalDisposition['Block_Web'] = True
    return finalDisposition

def toCSV(inputIPaddr,sourceApplcation, dataDict):
    '''
    Purpose: Take the disposition dictionary and convert to CSV
    Input: 
            inputIPaddr - string of input IP
            sourceApplcation - string of application name
            dataDict - dictionary 
    Returns: CSV string or nothing if error
    '''
    # Check to make sure all of the keys are present because if they are not then something is wrong
    if dataDict["disposition"]["inbound"] and dataDict["disposition"]["outbound"]:
        inEmail = dataDict["disposition"]["inbound"]["Block_Email"]
        inVPN = dataDict["disposition"]["inbound"]["Block_VPN"]
        inWeb = dataDict["disposition"]["inbound"]["Block_Web"]
        outEmail = dataDict["disposition"]["outbound"]["Block_Email"]
        outVPN = dataDict["disposition"]["outbound"]["Block_VPN"]
        outWeb = dataDict["disposition"]["outbound"]["Block_Web"]
        csv = "%s,%s,%s,%s,%s,%s,%s,%s" % (inputIPaddr,sourceApplcation,inEmail,inVPN,inWeb,outEmail,outVPN,outWeb)
        return csv
    else:
        print "Error converting to CSV. Missing inbound or outbound key."
        return

#
# Various API data pulls
#

def def_MaxMindGeoIPInsights(inputIPaddr,dotheCSV):
    ''' 
    Purpose: Gets geoip data from Maxmind Geoip Insights.
    Field discription: See Insights column on https://dev.maxmind.com/geoip/geoip2/web-services/#traits
    '''

    # Setup output
    outputDict = {}
    outputDict['module'] = 'Maxmind Geoip Insights'
    # Input and data collection
    indicatorToLookup = inputIPaddr
    client = geoip2.webservice.Client(userId, apiKey)
    responseAsObject = client.insights(indicatorToLookup) #object
    apiJsonResponse = json.dumps(responseAsObject.raw) #json
    apiDictResponse = json.loads(apiJsonResponse) #dict

    # Put data in its place
    # Raw
    outputDict['raw'] = apiDictResponse # capture raw response in dict

    # Currated
    outputDict['curated'] = apiDictResponse['traits']

    # Recomendation
    dispositionsInboundList = []
    dispositionsOutboundList = []
    if 'is_anonymous_vpn' in apiDictResponse['traits']:
        if apiDictResponse['traits']['is_anonymous_vpn'] == True:
            inbound = ['Block_VPN','Block_Email','Block_Web']
            outbound = ['Block_VPN','Block_Email','Block_Web']
            dispositionsInboundList.extend(inbound)
            dispositionsOutboundList.extend(outbound)
    if 'is_public_proxy' in apiDictResponse['traits']:
        if apiDictResponse['traits']['is_public_proxy'] == True:
            inbound = ['Block_VPN','Block_Email','Block_Web']
            outbound = ['Block_VPN','Block_Email','Block_Web']
            dispositionsInboundList.extend(inbound)
            dispositionsOutboundList.extend(outbound)
    if 'is_tor_exit_node' in apiDictResponse['traits']:
        if apiDictResponse['traits']['is_tor_exit_node'] == True:
            inbound = ['Block_VPN','Block_Email','Block_Web']
            outbound = ['Block_VPN','Block_Email','Block_Web']
            dispositionsInboundList.extend(inbound)
            dispositionsOutboundList.extend(outbound)
    if 'is_hosting_provider' in apiDictResponse['traits']:
        if apiDictResponse['traits']['is_hosting_provider'] == True:
            inbound = ['Block_VPN','Allow_Email','Allow_Web']
            outbound = ['Allow_VPN','Allow_Email','Allow_Web']
            dispositionsInboundList.extend(inbound)
            dispositionsOutboundList.extend(outbound)
    if 'user_type' in apiDictResponse['traits']:
        if apiDictResponse['traits']['user_type'] == 'residential':
            inbound = ['Allow_VPN','Block_Email','Allow_Web']
            outbound = ['Block_VPN','Block_Email','Block_Web']
            dispositionsInboundList.extend(inbound)
            dispositionsOutboundList.extend(outbound)
    if 'user_type' in apiDictResponse['traits']:
        if apiDictResponse['traits']['user_type'] == 'cellular':
            inbound = ['Allow_VPN','Block_Email','Allow_Web']
            outbound = ['Block_VPN','Block_Email','Block_Web']
            dispositionsInboundList.extend(inbound)
            dispositionsOutboundList.extend(outbound)
    if 'user_type' in apiDictResponse['traits']:
        if apiDictResponse['traits']['user_type'] == 'cafe':
            inbound = ['Allow_VPN','Block_Email','Allow_Web']
            outbound = ['Block_VPN','Block_Email','Block_Web']
            dispositionsInboundList.extend(inbound)
            dispositionsOutboundList.extend(outbound)
    if 'user_type' in apiDictResponse['traits']:
        if apiDictResponse['traits']['user_type'] == 'search_engine_spider':
            inbound = ['Block_VPN','Block_Email','Allow_Web']
            outbound = ['Block_VPN','Block_Email','Block_Web']
            dispositionsInboundList.extend(inbound)
            dispositionsOutboundList.extend(outbound)

    totalInboundCounts = {'Block_VPN': dispositionsInboundList.count("Block_VPN"),'Allow_VPN': dispositionsInboundList.count("Allow_VPN"),'Block_Email': dispositionsInboundList.count("Block_Email"),'Allow_Email': dispositionsInboundList.count("Allow_Email"),'Block_Web': dispositionsInboundList.count("Block_Web"),'Allow_Web': dispositionsInboundList.count("Allow_Web") }
    totalOutboundCounts = {'Block_VPN': dispositionsOutboundList.count("Block_VPN"),'Allow_VPN': dispositionsOutboundList.count("Allow_VPN"),'Block_Email': dispositionsOutboundList.count("Block_Email"),'Allow_Email': dispositionsOutboundList.count("Allow_Email"),'Block_Web': dispositionsOutboundList.count("Block_Web"),'Allow_Web': dispositionsOutboundList.count("Allow_Web") }

    outputDict['recommendation'] = {}
    outputDict['recommendation']['inbound'] = totalInboundCounts
    outputDict['recommendation']['outbound'] = totalOutboundCounts

    # Disposition
    outputDict['disposition'] = {}
    outputDict['disposition']['inbound'] = doDisposition(dispositionsInboundList)
    outputDict['disposition']['outbound'] = doDisposition(dispositionsOutboundList)

    # Output
    if dotheCSV == True:
        print toCSV(indicatorToLookup,"MaxMindGeoIPInsights",outputDict)
    else:
        print json.dumps(outputDict)


def def_grey(inputIPaddr,dotheCSV):
    '''
    Purpose: GreyNoise is a system that collects and analyzes data on Internet-wide scanners. GreyNoise collects data on benign scanners such as Shodan.io, as well as malicious actors like SSH and telnet worms. The data is collected by a network of sensors deployed around the Internet in various datacenters, cloud providers, and regions. https://github.com/GreyNoise-Intelligence/api.greynoise.io
    '''
    # Setup output
    outputDict = {}
    outputDict['module'] = 'GreyNoise'
    recentResultsList = []
    # Input and data collection
    indicatorToLookup = inputIPaddr
    url = 'http://api.greynoise.io:8888/v1/query/ip'
    payload = {'ip': indicatorToLookup}
    apiJsonResponse = fraudlabspro_api_request(url,payload) #json
    apiDictReponse = json.loads(apiJsonResponse) #dict

    # Function needed to determine type and if needed extract the protocol type from string. Makes the output.
    def stringExtraction(input,age):
        ''' 
            Input: dict,str
            Output: dict or None
        '''
        if 'activity' in input['category']:
            tag_id = input['name']
            if "WEB_CRAWLER" in tag_id: # I dont like how this one is categorized so calling it what Ill call search_engine
                return {"name":input['name'],"how_recent":age,"purpose":"web_crawler","Inbound":['Block_VPN','Block_Email','Allow_Web'],"Outbound":['Block_VPN','Block_Email','Allow_Web']}
            else:
                if "HIGH" in tag_id or "LOW" in tag_id or "MEDIUM" in tag_id: # used to extract protocol
                    protocol = tag_id.split("_")[0].replace("HTTP","WEB") #e.g. SOCKS_PROXY_SCANNER_LOW
                    if "high" in input['confidence']: # if high confidence scaner then block
                        return {"name":input['name'],"type":protocol,"how_recent":age,"purpose":"scanner","Inbound":['Block_VPN','Block_Email','Block_Web'],"Outbound":['Block_VPN','Block_Email','Block_Web']}
                    else:
                        return {"name":input['name'],"type":protocol,"how_recent":age,"purpose":"scanner","Inbound":"","Outbound":""}
                else:
                    return {"name":input['name'],"type":None,"how_recent":age,"purpose":"scanner","Inbound":"","Outbound":""}
        if 'worm' in input['category']:
            return {"name":input['name'],"how_recent":age,"purpose":"worm","Inbound":['Block_VPN','Block_Email','Block_Web'],"Outbound":['Block_VPN','Block_Email','Block_Web']}
        if 'search_engine' in input['category']:
            return {"name":input['name'],"how_recent":age,"purpose":"web_crawler","Inbound":['Allow_VPN','Allow_Email','Allow_Web'],"Outbound":['Allow_VPN','Allow_Email','Allow_Web']}
        if 'actor' in input['category']: # current data shows actor is shodan, censys, universitiy research, shadowserver, etc. 
            return {"name":input['name'],"how_recent":age,"purpose":"actor","Inbound":['Allow_VPN','Allow_Email','Allow_Web'],"Outbound":['Allow_VPN','Allow_Email','Allow_Web']}
        if 'tool' in input['category']:
            return {"name":input['name'],"how_recent":age,"purpose":"tool","Inbound":"","Outbound":""}
        if 'TOR' in input['name']:
            return {"name":input['name'],"how_recent":age,"purpose":"anonymous","Inbound":['Block_VPN','Block_Email','Allow_Web'],"Outbound":['Block_VPN','Block_Email','Block_Web']}
        else:
            print "### GreyNoise parse error: %s: " % input
            return {"Status":"Parse Error"}

    # Put data in its place
    # Raw
    outputDict['raw'] = apiDictReponse # capture raw response in dict

    # Currated
    if 'status' in apiDictReponse:
        if 'ok' not in apiDictReponse['status']: # ok means scuccess otherwise we want to know what is going on
            outputDict['currated'] = apiDictReponse['status']
            outputDict['disposition'] = {}
            outputDict['disposition']['inbound'] = {'Block_Email': None, 'Block_VPN': None, 'Block_Web': None}
            outputDict['disposition']['outbound'] = {'Block_Email': None, 'Block_VPN': None, 'Block_Web': None}

        else:
            for record in apiDictReponse['records']:
                scannerDict = {}
                # Only records that have occured within the last month, and last week are of interest
                utc=pytz.UTC # Not all timestamps coming in have TZ so must give UTC to everything
                today = datetime.today().replace(tzinfo=utc) # todays date
                dateFirstSeen = parse(record['first_seen']).replace(tzinfo=utc) # first time tag given
                dateLastUpdated = parse(record['last_updated']).replace(tzinfo=utc) # last time tag given
                delta = today - dateLastUpdated
                if delta < timedelta(minutes=10080): # number of minutes in 1 week 
                    recentResultsList.append(stringExtraction(record,"within 1 week"))
                elif delta < timedelta(minutes=43800): # number of minutes in 1 month
                    recentResultsList.append(stringExtraction(record,"within 1 month"))
                elif delta < timedelta(minutes=131400): # number of minutes in 3 month
                    recentResultsList.append(stringExtraction(record,"within 3 month"))
                elif delta < timedelta(minutes=262800): # number of minutes in 6 month
                    recentResultsList.append(stringExtraction(record,"within 6 month"))
                elif delta < timedelta(minutes=394200): # number of minutes in 9 month
                    recentResultsList.append(stringExtraction(record,"within 9 month"))
                elif delta < timedelta(minutes=525601): # number of minutes in 12 month
                    recentResultsList.append(stringExtraction(record,"within 12 month"))
                elif delta > timedelta(minutes=525601): # number of minutes in 12 month GREATER THAN
                    recentResultsList.append(stringExtraction(record,"older than 12 month"))
            outputDict['curated'] = recentResultsList # collection of all scanner data found
             

            #Voting. Only focuses on recent activity.
            dispositionsInboundList = []
            dispositionsOutboundList = []
            
            for result in outputDict['curated']:
                if 'within 1 month' in result['how_recent'] or 'within 1 week' in result['how_recent']:
                    Inbound = result.get('Inbound', None) # collect all dispositions
                    Outbound = result.get('Outbound', None) # collect all dispositions
                    dispositionsInboundList.extend(Inbound)
                    dispositionsOutboundList.extend(Outbound)

            totalInboundCounts = {'Block_VPN': dispositionsInboundList.count("Block_VPN"),'Allow_VPN': dispositionsInboundList.count("Allow_VPN"),'Block_Email': dispositionsInboundList.count("Block_Email"),'Allow_Email': dispositionsInboundList.count("Allow_Email"),'Block_Web': dispositionsInboundList.count("Block_Web"),'Allow_Web': dispositionsInboundList.count("Allow_Web") }
            totalOutboundCounts = {'Block_VPN': dispositionsOutboundList.count("Block_VPN"),'Allow_VPN': dispositionsOutboundList.count("Allow_VPN"),'Block_Email': dispositionsOutboundList.count("Block_Email"),'Allow_Email': dispositionsOutboundList.count("Allow_Email"),'Block_Web': dispositionsOutboundList.count("Block_Web"),'Allow_Web': dispositionsOutboundList.count("Allow_Web") }

            outputDict['voting'] = {}
            outputDict['voting']['inbound'] = totalInboundCounts
            outputDict['voting']['outbound'] = totalOutboundCounts

            # Disposition
            outputDict['disposition'] = {}
            outputDict['disposition']['inbound'] = doDisposition(dispositionsInboundList)
            outputDict['disposition']['outbound'] = doDisposition(dispositionsOutboundList)

    # Output
    if dotheCSV == True:
        print toCSV(indicatorToLookup,"GreyNoise",outputDict)
    else:
        print json.dumps(outputDict)
        


def def_fraudlabsproip(inputIPaddr,dotheCSV):
    '''
    Purpose: Query IP against Fraud Labs Pro free API. 
    https://www.fraudlabspro.com/developer/api/screen-order
    '''
    # Setup output
    outputDict = {}
    outputDict['module'] = 'Fraud Labs Pro'
    # Input and data collection
    indicatorToLookup = inputIPaddr
    url = 'https://api.fraudlabspro.com/v1/order/screen'
    payload = {'key': FraudLabsapiKey, 'ip': indicatorToLookup, 'format': 'json'}
    apiJsonResponse = fraudlabspro_api_request(url,payload) #json
    apiDictReponse = json.loads(apiJsonResponse) #dict

    # Put data in its place
    # Raw
    outputDict['raw'] = apiDictReponse # capture raw response in dict

    # Currated
    outputDict['curated'] = {k:v for k,v in apiDictReponse.items() if v != 'NA'} # The API returns NA for many values so this builds a new dictionary without any keys that contain a value of NA

    # Voting
    dispositionsInboundList = []
    dispositionsOutboundList = []

    # Section uses Fraudlabs status, distribution, and score
    if apiDictReponse['fraudlabspro_status'] == "REVIEW" or apiDictReponse['fraudlabspro_status'] == "REJECT":
        inbound = ['Block_VPN','Block_Email','Block_Web']
        outbound = ['Block_VPN','Block_Email','Block_Web']
        dispositionsInboundList.extend(inbound)
        dispositionsOutboundList.extend(outbound)
    elif apiDictReponse['fraudlabspro_score'] >= 90 and apiDictReponse['fraudlabspro_distribution'] >= 90:
        inbound = ['Block_VPN','Block_Email','Block_Web']
        outbound = ['Block_VPN','Block_Email','Block_Web']
        dispositionsInboundList.extend(inbound)
        dispositionsOutboundList.extend(outbound)
    elif apiDictReponse['fraudlabspro_score'] >= 80:
        inbound = ['Block_VPN','Block_Email','Block_Web']
        outbound = ['Block_VPN','Block_Email','Block_Web']
        dispositionsInboundList.extend(inbound)
        dispositionsOutboundList.extend(outbound)
    elif apiDictReponse['fraudlabspro_score'] >= 40:
        inbound = ['Block_VPN','Block_Email','Allow_Web']
        outbound = ['Block_VPN','Block_Email','Allow_Web']
        dispositionsInboundList.extend(inbound)
        dispositionsOutboundList.extend(outbound)
    elif apiDictReponse['fraudlabspro_score'] >= 20:
        inbound = ['Block_VPN','Block_Email','Allow_Web']
        outbound = ['Block_VPN','Block_Email','Allow_Web']
        dispositionsInboundList.extend(inbound)
        dispositionsOutboundList.extend(outbound)
    else:
        inbound = ['Allow_VPN','Allow_Email','Allow_Web']
        outbound = ['Allow_VPN','Allow_Email','Allow_Web']
        dispositionsInboundList.extend(inbound)
        dispositionsOutboundList.extend(outbound)

    # Section uses Fraudlabs IP usage type
    if apiDictReponse['ip_usage_type'] == "Mobile ISP":
        inbound = ['Allow_VPN','Block_Email','Allow_Web']
        outbound = ['Block_VPN','Block_Email','Block_Web']
        dispositionsInboundList.extend(inbound)
        dispositionsOutboundList.extend(outbound)
    elif apiDictReponse['ip_usage_type'] == "Data Center/Web Hosting/Transit":
        inbound = ['Block_VPN','Block_Email','Block_Web']
        outbound = ['Allow_VPN','Allow_Email','Allow_Web']
        dispositionsInboundList.extend(inbound)
        dispositionsOutboundList.extend(outbound)
    elif apiDictReponse['ip_usage_type'] == "Search Engine Spider":
        inbound = ['Allow_VPN','Allow_Email','Allow_Web']
        outbound = ['Block_VPN','Block_Email','Allow_Web']
        dispositionsInboundList.extend(inbound)
        dispositionsOutboundList.extend(outbound)

    # Section uses Fraudlabs IP proxy and blacklist (INCOMPLETE)
    if apiDictReponse['is_proxy_ip_address'] == "Y":
        inbound = ['Block_VPN','Block_Email','Allow_Web']
        outbound = ['Block_VPN','Block_Email','Block_Web']
        dispositionsInboundList.extend(inbound)
        dispositionsOutboundList.extend(outbound)
    if apiDictReponse['is_ip_blacklist'] == "Y":
        inbound = ['Block_VPN','Block_Email','Block_Web']
        outbound = ['Block_VPN','Block_Email','Block_Web']
        dispositionsInboundList.extend(inbound)
        dispositionsOutboundList.extend(outbound)

    totalInboundCounts = {'Block_VPN': dispositionsInboundList.count("Block_VPN"),'Allow_VPN': dispositionsInboundList.count("Allow_VPN"),'Block_Email': dispositionsInboundList.count("Block_Email"),'Allow_Email': dispositionsInboundList.count("Allow_Email"),'Block_Web': dispositionsInboundList.count("Block_Web"),'Allow_Web': dispositionsInboundList.count("Allow_Web") }
    totalOutboundCounts = {'Block_VPN': dispositionsOutboundList.count("Block_VPN"),'Allow_VPN': dispositionsOutboundList.count("Allow_VPN"),'Block_Email': dispositionsOutboundList.count("Block_Email"),'Allow_Email': dispositionsOutboundList.count("Allow_Email"),'Block_Web': dispositionsOutboundList.count("Block_Web"),'Allow_Web': dispositionsOutboundList.count("Allow_Web") }

    outputDict['voting'] = {}
    outputDict['voting']['inbound'] = totalInboundCounts
    outputDict['voting']['outbound'] = totalOutboundCounts
    
    # Disposition
    outputDict['disposition'] = {}
    outputDict['disposition']['inbound'] = doDisposition(dispositionsInboundList)
    outputDict['disposition']['outbound'] = doDisposition(dispositionsOutboundList)

    # Output
    if dotheCSV == True:
        print toCSV(indicatorToLookup,"FraudLabsPro",outputDict)
    else:
        print json.dumps(outputDict)


def def_MaxmindMinfraudIPscore(inputIPaddr,dotheCSV):
    '''
    Purpose: Maxmind Minfraud Score. 
    '''
    # Setup output
    outputDict = {}
    outputDict['module'] = 'Maxmind Minfraud'
    # Input and data collection
    indicatorToLookup = inputIPaddr
    url = 'https://minfraud.maxmind.com/minfraud/v2.0/score'
    payload = json.dumps({'device': {'ip_address': indicatorToLookup}}) #dict to string
    apiJsonResponse = maxmind_api_request(url,payload) #json
    apiDictReponse = json.loads(apiJsonResponse) #dict

    # Raw
    outputDict['raw'] = apiDictReponse # capture raw response in dict

    # Currated
    apiDictReponse['ip'] = indicatorToLookup # dict
    outputDict['curated'] = {'ip':apiDictReponse['ip'], 'ip_risk_score': apiDictReponse['ip_address']['risk'], 'transaction_risk_score': apiDictReponse['risk_score']} # dict

    def doVoting(riskScoreNumber,sourceApp):
        '''
        Purpose: Do voting on actions based on risk score
        Input: float
        Output: tuple e.g. ({'Allow_Email': 1, 'Block_VPN': 0, 'Allow_VPN': 1, 'Allow_Web': 1, 'Block_Email': 0, 'Block_Web': 0}, ['Allow_VPN', 'Allow_Email', 'Allow_Web'], {'Allow_Email': 1, 'Block_VPN': 0, 'Allow_VPN': 1, 'Allow_Web': 1, 'Block_Email': 0, 'Block_Web': 0}, {'Allow_Email': 1, 'Block_VPN': 0, 'Allow_VPN': 1, 'Allow_Web': 1, 'Block_Email': 0, 'Block_Web': 0})
        '''
        dispositionsInboundList = []
        dispositionsOutboundList = []
        
        if riskScoreNumber >= 90:
            inbound = ['Block_VPN','Block_Email','Block_Web']
            outbound = ['Block_VPN','Block_Email','Block_Web']
            dispositionsInboundList.extend(inbound)
            dispositionsOutboundList.extend(outbound)
        elif riskScoreNumber >= 80:
            inbound = ['Block_VPN','Block_Email','Block_Web']
            outbound = ['Block_VPN','Block_Email','Block_Web']
            dispositionsInboundList.extend(inbound)
            dispositionsOutboundList.extend(outbound)
        elif riskScoreNumber >= 70:
            inbound = ['Block_VPN','Block_Email','Allow_Web']
            outbound = ['Block_VPN','Block_Email','Allow_Web']
            dispositionsInboundList.extend(inbound)
            dispositionsOutboundList.extend(outbound)
       # elif riskScoreNumber >= 20:
       #     inbound = ['Block_VPN','Allow_Email','Allow_Web']
       #     outbound = ['Block_VPN','Allow_Email','Allow_Web']
       #     dispositionsInboundList.extend(inbound)
       #     dispositionsOutboundList.extend(outbound)
        else:
            inbound = ['Allow_VPN','Allow_Email','Allow_Web']
            outbound = ['Allow_VPN','Allow_Email','Allow_Web']
            dispositionsInboundList.extend(inbound)
            dispositionsOutboundList.extend(outbound)
        
        totalInboundCounts = {'Block_VPN': dispositionsInboundList.count("Block_VPN"),'Allow_VPN': dispositionsInboundList.count("Allow_VPN"),'Block_Email': dispositionsInboundList.count("Block_Email"),'Allow_Email': dispositionsInboundList.count("Allow_Email"),'Block_Web': dispositionsInboundList.count("Block_Web"),'Allow_Web': dispositionsInboundList.count("Allow_Web") }
        totalOutboundCounts = {'Block_VPN': dispositionsOutboundList.count("Block_VPN"),'Allow_VPN': dispositionsOutboundList.count("Allow_VPN"),'Block_Email': dispositionsOutboundList.count("Block_Email"),'Allow_Email': dispositionsOutboundList.count("Allow_Email"),'Block_Web': dispositionsOutboundList.count("Block_Web"),'Allow_Web': dispositionsOutboundList.count("Allow_Web") }

        return dispositionsInboundList,dispositionsOutboundList,totalInboundCounts,totalOutboundCounts

    # Voting
    outputDict['voting'] = {}
    # There are two risk scores: One for IP and one for merchant transaction. Going to use the highest number for voting.
    highestRiskScore = max(apiDictReponse['ip_address']['risk'],apiDictReponse['risk_score'])
    allVoting = doVoting(highestRiskScore,"MaxmindMinfraudIPscore")
    inboundVotingList = allVoting[0] # inbound
    outboundVotingList = allVoting[1] # outbound
    inboundVotingCount = allVoting[2] # inbound
    outboundVotingCount = allVoting[3] # outbound
    outputDict['voting']['inbound'] = inboundVotingCount
    outputDict['voting']['outbound'] = outboundVotingCount

    # Disposition
    outputDict['disposition'] = {}
    outputDict['disposition']['inbound'] = doDisposition(inboundVotingList)
    outputDict['disposition']['outbound'] = doDisposition(outboundVotingList)

    # Output
    if dotheCSV == True:
        print toCSV(indicatorToLookup,"MaxmindMinfraudIPscore",outputDict)
    else:
        print json.dumps(outputDict)


def def_shodan(inputIPaddr,dotheCSV):
    '''
    Purpose: Search Shodan and see if there CVEs. 
    '''

    api = shodan.Shodan(SHODAN_API_KEY)
    
    # Setup output
    outputDict = {}
    outputDict['module'] = 'shodan'
    # Input and data collection
    indicatorToLookup = inputIPaddr
    try:
        hostdata = api.host(indicatorToLookup, minify=False, history=True) # history provides all available records for searched IP
        apiDictResponse = hostdata['data'] # dict
        apiJsonResponse = json.dumps(apiDictResponse) #json
        
        # Put data in its place
        # Raw TOO MUCH DATA so commenting it out
        #outputDict['raw'] = apiDictResponse # capture raw response in dict
        outputDict['raw'] = "disabled. Too much data on STDOUT. Uncomment in code if you want to see it."
        
        # Currated
        outputDict['curated'] = {}
        count = 0 # needed because history is displayed a new key for each item
        for item in apiDictResponse:
            vulnlist = []
            historyDict = {}
            count +=1
        
            # Focusing only on recent scan results. Only will print anything newer than 2 weeks.
            # Only will print if CVE is found
            if "timestamp" in item:
                utc=pytz.UTC # Give UTC to everything
                today = datetime.today().replace(tzinfo=utc) # todays date
                dateSeen = parse(item['timestamp']).replace(tzinfo=utc) # time of scan result
                delta = today - dateSeen
                if delta < timedelta(minutes=20160): # number of minutes in 2 weeks
                    #historyDict['timestamp2'] = "within 2 weeks"
                    # Will only print if CVE is found
                    if "vulns" in item:
                        historyDict['timestamp'] = item['timestamp']
                        #print type(item["vulns"]) #dict
                        for key, value in item['vulns'].iteritems() :
                            #cve_tf = key, value['verified']
                            vulnlist.append(key)
                        historyDict['cve_count'] = len(vulnlist)
                        historyDict['cve_list'] = vulnlist
                        if "ip_str" in item:
                            historyDict['ip_address'] = item['ip_str']
                        if "cpe" in item:
                            historyDict['cpe'] = item['cpe']
                        if "_shodan" in item:
                            if "module" in item['_shodan']:
                                historyDict['scan_module'] = item['_shodan']['module']
         
                        outputDict['curated'][count] = historyDict
        
            # Voting
            # Unlike the otherm modules, this one is not worried about protocol. If there are vulnerabilities at the IP, then no communication is allowed. The Shodan does contain protocol, ports, and applications which could be used to be more grainular on the decisions. However, the server could be secure on web, email, and VPN but not sql. So I decided that if anything is vulnerabile then burn it with fire.
            # Future - would like to search by tag. If it is a webcam or has default passwords, then block. Looks to be an enterprise API only feature.
            outputDict['voting'] = {}
            outputDict['disposition'] = {}
            if outputDict['curated']:
                outputDict['voting']['inbound'] = "BLOCK"
                outputDict['voting']['outbound'] = "BLOCK"
                outputDict['disposition']['inbound'] = {'Block_Email': True, 'Block_VPN': True, 'Block_Web': True}
                outputDict['disposition']['outbound'] = {'Block_Email': True, 'Block_VPN': True, 'Block_Web': True}
            else:
                outputDict['voting']['inbound'] = None
                outputDict['voting']['outbound'] = None
                outputDict['disposition']['inbound'] = {'Block_Email': None, 'Block_VPN': None, 'Block_Web': None}
                outputDict['disposition']['outbound'] = {'Block_Email': None, 'Block_VPN': None, 'Block_Web': None}
    
    except shodan.exception.APIError, e:  # e.g. Error: No information available for that IP.
        #print('Error: {}'.format(e))
        outputDict['raw'] = 'Error: {}'.format(e)
        outputDict['voting'] = None
        outputDict['disposition'] = {}
        outputDict['disposition']['inbound'] = {'Block_Email': None, 'Block_VPN': None, 'Block_Web': None}
        outputDict['disposition']['outbound'] = {'Block_Email': None, 'Block_VPN': None, 'Block_Web': None}

    if dotheCSV == True:
        print toCSV(indicatorToLookup,"Shodan",outputDict)
    else:
        print json.dumps(outputDict)


#       #
# START #
#       #

# Runs all the things. Good luck.
if args.converttocsv:
    makeMeCSV = True
else:
    makeMeCSV = False

if args.doAllChecks:
    def_MaxMindGeoIPInsights(args.ipAddr,makeMeCSV)
    def_grey(args.ipAddr,makeMeCSV)
    def_fraudlabsproip(args.ipAddr,makeMeCSV)
    def_MaxmindMinfraudIPscore(args.ipAddr,makeMeCSV)
    def_shodan(args.ipAddr,makeMeCSV)
else:
    if args.MaxMindGeoIPInsights:
        def_MaxMindGeoIPInsights(args.ipAddr,makeMeCSV)
    if args.grey:
        def_grey(args.ipAddr,makeMeCSV)
    if args.fraudlabsproip:
        def_fraudlabsproip(args.ipAddr,makeMeCSV)
    if args.MaxmindMinfraudIPscore:
        def_MaxmindMinfraudIPscore(args.ipAddr,makeMeCSV)
    if args.shodan:
        def_shodan(args.ipAddr,makeMeCSV)

