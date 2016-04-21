#!/usr/bin/env python


import sys, string
#from xml.dom.minidom import parseString
#from elementtree import ElementTag as ET
#from elementtree.ElementTree import Element
#from elementtree.ElementTree import Parse
#import elementtree.ElementTree as ET
from lxml import etree as ET


InputFile = sys.argv[1]
#ReportName = "<Report name="


#def file_read():
#fr = open('InputFile', 'r')
#scan = fr.read()
#fr.close()
#return fr



#def main():

#print InputFile #for testing
#fr = open(InputFile, 'r') #open the file read only
#data = fr.read() #read the data from the file to an object
#fr.close() #close the file
#re.search(ReportName)

#tree = parse(InputFile
#elem = tree.getroot()



tree = ET.parse(InputFile)
doc = tree.getroot()
#report = ET.SubElement(doc, "Report")
#reporthost = ET.SubElement(doc, "ReportHost")
#print document.
#doc = ET.Element("NessusClientData_v2")
#Pref = ET.SubElement(doc, "ServerPreferences")
#pref = ET.SubElement(Pref, "value")
#name = ET.SubElement(pref, "name")
#Target = doc.find('Hostproperties')
##print RName[0].attrib #this prints the host name

#for k in RName.iteritems():
#	print k


RName = doc.find('Report') #this gets me the report name

#Getting the number of hosts
#--------------------#
NumHosts = 0 #used for counting the number of hosts
ReportHost = "ReportHost"
Hosts = doc.getiterator(ReportHost)
for item in Hosts:
  NumHosts +=1

#--------------------#

#print statements
#-----------------------#
print ('Report Name: ' + RName.attrib['name']) #this prints the report name
print ('Total Number of Hosts Scanned: %d' %(NumHosts))

#------------------------#

#Get indiv. host infomation
#--------------------#
number = 0
a = 1 #this is the host number, in ascending order, not necesaary just for looks
Report = "Report" #the search term for the report nmame
OS = ".//tag[@name='operating-system']" #this will get the OS Name
HostIP = ".//tag[@name='host-ip']" #this will get the host IP
HostStart = ".//tag[@name='HOST_START']" #this will get the host scan start time
HostEnd = ".//tag[@name='HOST_END']" #this will get the host scan end time
ItemSeverity = ".//ReportItem[@severity='3']" #this is the severity level


HostNum = NumHosts -1 #this needs to be set to minus 1 or else you get out of range error
#I reversed the order on purpose or else the hosts would list in reverse alpha and that's ugly
HostName = doc.find(Report)
OSystem = doc.findall(OS)
HIP = doc.findall(HostIP)
HStart = doc.findall(HostStart)
HEnd = doc.findall(HostEnd)
ISeverity = doc.findall(ItemSeverity)

while HostNum != -1: #this cannot be zero or you don't get the last host
  print ('Host Number: %d' %(a))
print ('Host Name: ' + HostName[HostNum].attrib['name']) #this will print out the host name in alpha order
print ('Host IP: ' + HIP[HostNum].text)
print ('Operating System: ' + OSystem[HostNum].text)
print ('Start Time: ' + HStart[HostNum].text)
print ('End Time: ' + HEnd[HostNum].text)
print ('Infomation: ') #this will be the reported items only with severity of 2 or greater
#ISeverity = report.findall(ItemSeverity)
for item in ISeverity[HostNum]:
  print ISeverity[HostNum].attrib #this only prints out the first item so far, I want all items for each host

print ('')
HostNum -=1 #decrement the number of hosts till zero
a +=1 #increment the host number, not necessary just for looks



#--------------------#

print test.attrib['name']
print item
print a
print NumHosts
print Target
pref = ET.SubElement(root, "preference")
for subelement in pref
    print subelement.text
target = ET.SubElement(pref, "name")

dom = parseString(data)
xmlTag = dom.getElementsByTagName('<HostProperties>')[0].toxml()
xmlData = xmlTag.replace('<HostProperties>','').replace('<HostProperties>','')
print xmltag
print xmldata


if __name__ == "__main__":
	main()



set $(cat $InputFile | awk -v ReportHostName="$ReportHostName" '$0 ~ ReportHostName {n++}; END {print n+0 }')


