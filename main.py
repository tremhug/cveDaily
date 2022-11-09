import requests
import json
from datetime import timedelta
from datetime import datetime


###### Constantes pour les couleurs
CRITIQUE = "\033[0;30;41m"
HAUTE = "\033[0;30;43m"
MOYENNE = "\033[0;30;44m"
BASSE = "\033[0;30;42m"
RESET = "\033[0;0m"
#####



current = datetime.today()
currentStr = current.strftime("%Y-%d-%mT%H:%M:%S")
yesterday = current - timedelta(days=1)
yesterdayStr = yesterday.strftime("%Y-%d-%mT%H:%M:%S")
print(currentStr,"---",yesterdayStr)
cve_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate="+yesterdayStr+"&pubEndDate="+currentStr
print(cve_url)
response = requests.get(cve_url)
jsonCve = response.json()

print (type (jsonCve))
for vuln in jsonCve["vulnerabilities"]:
    cves = vuln.values()
    i=0
    for cve in cves:
        id = cve["id"]
        desc = cve["descriptions"]
        metrics = cve["metrics"].values()
        
        for metric in metrics:
            if metric:
                cvssDatas = metric[0]["cvssData"]
                couleurText = ""
                if cvssDatas["version"]=="3.0": #adapter pour 3.1 ou autre
                    score = float(cvssDatas["baseScore"])
                    if score >= 9.0:
                        couleurText = CRITIQUE
                    elif score >= 7.0 and score < 9.0:
                        couleurText = HAUTE
                    elif score >= 5.0 and score < 7.0:
                        couleurText = MOYENNE
                    else:
                        couleurText = BASSE

                    print("\n\n",id,"\n", desc,"\n","baseScore: ", couleurText+str(cvssDatas["baseScore"])+RESET)
