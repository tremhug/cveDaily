import requests
import json
from datetime import timedelta
from datetime import datetime
import sys

###### RAPPORT N'AJOUTE PAS LES COULEURS ET PEUT ETRE > DANS UN FICHIER
###### CONSOLE AFFICHERA LE RESULTAT DANS LA CONSOLE
if len(sys.argv) > 1:
    OUTPUT = sys.argv[1]
else:
    OUTPUT = "RAPPORT" #CONSOLE ou RAPPORT

###### Constantes pour les couleurs
if OUTPUT == "CONSOLE":
    HEADER=""
    CRITIQUE = "\033[0;30;41m"
    HAUTE = "\033[0;30;43m"
    MOYENNE = "\033[0;30;44m"
    BASSE = "\033[0;30;42m"
    RESET = "\033[0;0m"
    CR = "\n"
    FOOTER =""
    BOLD = ""
    ENDBOLD = "\n"
else:
    HEADER="<HTML><HEAD/><body style=\"font-family:verdana\">"
    CRITIQUE="<font style=\"background-color:RED;color:white\">"
    HAUTE = "<font style=\"background-color:YELLOW;color:black\">"
    MOYENNE = "<font style=\"background-color:BLUE;color:white\">"
    BASSE = "<font style=\"background-color:GREEN;color:WHITE\">"
    RESET = "</font>"
    CR = "<BR/>"
    FOOTER="</body></HTML>"
    BOLD= "<H3>"
    ENDBOLD = "</H3>"
#####



current = datetime.today()
currentStr = current.strftime("%Y-%d-%mT%H:%M:%S")
yesterday = current - timedelta(days=1)
yesterdayStr = yesterday.strftime("%Y-%d-%mT%H:%M:%S")
print(BOLD,yesterdayStr,"---",currentStr)
cve_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate="+yesterdayStr+"&pubEndDate="+currentStr
print(CR+"URL vers l'API -> "+cve_url+ENDBOLD)
response = requests.get(cve_url)
jsonCve = response.json()
print(HEADER)
#print (type (jsonCve))
for vuln in jsonCve["vulnerabilities"]:
    cves = vuln.values()
    i=0
    for cve in cves:
        id = cve["id"]
        desc = cve["descriptions"]
        description =""
        for d in desc:
            if d["lang"]=="en":
                description = d["value"]
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
                    print(CR+CR,BOLD+id+ENDBOLD, description,CR,"Score CVSS: ", couleurText+str(cvssDatas["baseScore"])+RESET)
print(FOOTER)
                    

