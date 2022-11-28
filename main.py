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
    CRITIQUE="<font style=\"background-color:#e9290f;color:white\"><div style=\"background-color:#e9290f;color:white;width:25%;\" >"
    HAUTE = "<font style=\"background-color:  #e98a0f;color:black\"><div style=\"background-color:  #e98a0f;color:black;width:25%;\" >"
    MOYENNE = "<font style=\"background-color:#fafa03;color:black\"><div style=\"background-color:#fafa03;color:black;width:25%;\" >"
    BASSE = "<font style=\"background-color:lime;color:black\"><div style=\"background-color:lime;color:black;width:25%;\" >"
    RESET = "</div></font>"
    CR = "<BR/>"
    FOOTER="</body></HTML>"
    BOLD= "<H3>"
    ENDBOLD = "</H3>"
#####

current = datetime.today()
currentStr = current.strftime("%Y-%m-%dT%H:%M:%S")
yesterday = current - timedelta(days=1)
yesterdayStr = yesterday.strftime("%Y-%m-%dT00:00:00")
cve_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate="+yesterdayStr+"&pubEndDate="+currentStr
#cve_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate="+yesterdayStr+"&lastModEndDate="+currentStr

print(HEADER) #Prints HTML header if RAPPORT
print(BOLD,yesterdayStr,"---",currentStr) #Prints dates for the report
print(CR+"URL vers l'API -> "+cve_url+ENDBOLD) #prints the URL to the NIST API

print(CRITIQUE,"CRITIQUE -  CVSS >=9",RESET,CR)
print(HAUTE, "HAUTE -  7<=CVSS<9 ", RESET,CR)
print(MOYENNE,"MOYENNE -  5<=CVSS<7", RESET,CR)
print(BASSE, "BASSE -  CVSS <5",RESET,CR)


response = requests.get(cve_url)
jsonCve = response.json()

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
                if cvssDatas["version"]=="3.0" or cvssDatas["version"]=="3.1": #adapter pour 3.1 ou autre
                    score = float(cvssDatas["baseScore"])
                    if score >= 9.0:
                        couleurText = CRITIQUE
                    elif score >= 7.0 and score < 9.0:
                        couleurText = HAUTE
                    elif score >= 5.0 and score < 7.0:
                        couleurText = MOYENNE
                    else:
                        couleurText = BASSE
                    AnchorOn = "<A href=\"https://nvd.nist.gov/vuln/detail/"+id+"\">"
                    AnchorOff = "</A>"
                    print(CR+CR,BOLD+AnchorOn+id+AnchorOff+ENDBOLD, description,CR,"Score CVSS: ", couleurText+str(cvssDatas["baseScore"])+RESET)
print(FOOTER)
