import xml.etree.ElementTree as ET

with open('checkthis') as f:
    lines = f.read()
lines = lines.splitlines() #we don't want no newlines

tree = ET.parse('openssl.xml')
doc = tree.getroot()

for issue in doc:
	for details in issue:
		if 'version' in details.attrib: #Only actual CVEs, skip the rest (Creds n stuff)
				if details.attrib["version"] in lines: #If that CVE concerns a version we are testing for...
						
						impact=""
						if issue.find("impact") is None: #Not all cves come with an impact rating because reasons...
							continue
						else:
							impact=" "+issue.find("impact").attrib["severity"]


						print "hit for: ",  details.attrib["version"] #Debug shit
						print "CVE"+issue.find("cve").attrib["name"] + impact
						

						if len(issue.find("description").text)>300:
							print issue.find("description").text[0:300]
						
						print "Affected:"
						for affects in issue.iter("affects"):
							print affects.attrib["version"]
						print "Fixed in: "+ issue.find("fixed").attrib["version"]

						print "---------------------------------------------------"

