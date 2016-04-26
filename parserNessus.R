#' Get policy preferences of the report - XML format
#'
#' @param doc 
#'
#' @return
#' @export
#'
#' @examples
GetPreferencesPolicy <- function(doc) {
  xpath <- paste("//NessusClientData_v2/Policy/Preferences", sep = "")
  return(XML::xpathApply(doc, xpath)[[1]])
}


#' Get all report data - XML format
#'
#' @param doc 
#'
#' @return
#' @export
#'
#' @examples
GetReport <- function(doc) {
  xpath <- "//NessusClientData_v2/Report"
  return(XML::xpathApply(doc, xpath)[[1]])
}


#' Gets the number of hosts on the report
#'
#' @param doc 
#'
#' @return
#' @export
#'
#' @examples
GetNumberOfHosts <- function(doc) {
  xml_report <- GetReport(doc)
  xpath <- "//Report/ReportHost"
  return(length((XML::xpathApply(xml_report, xpath))))
}

#' Gets the IP of the host 'hostnumber'
#'
#' @param doc 
#'
#' @return
#' @export
#'
#' @examples
GetIPofHostnumber <- function(doc, hostnumber = 1) {
  xml_report <- GetReport(doc)
  xpath <- paste("//Report/ReportHost[", hostnumber ,"] /@name", sep = "")
  return(unlist((XML::xpathApply(xml_report, xpath)))[["name"]])
}

#' Gets the XML of the given host
#'
#' @param doc 
#' @param hostnumber 
#'
#' @return
#' @export
#'
#' @examples
GetXMLHost <- function(doc, hostnumber=1) {
  xml_report <- GetReport(doc)
  xpath <- paste("//Report/ReportHost[", hostnumber ,"]", sep = "")
  return(XML::xpathApply(xml_report, xpath))[[1]]
}


#' Get the number of vulnerabilities of the host 'hostnumber'
#'
#' @param doc 
#' @param hostnumber 
#'
#' @return
#' @export
#'
#' @examples
GetNumberOfVuls <- function(doc, hostnumber=1) {
  xml_host <- GetXMLHost(doc = doc, hostnumber = hostnumber)
  xpath <- "//ReportHost/ReportItem"
  return(length(XML::xpathApply(xml_host, xpath)))
}

#' Get the the properties of a host given its order in a report
#'
#' @param doc 
#' @param hostnumber 
#'
#' @return
#' @export
#'
#' @examples
GetHostProperties <- function(doc, hostnumber=1) {
  xml_host <- GetXMLHost(doc, hostnumber)
  xpath <- "//ReportHost/HostProperties"
  return(XML::xpathApply(xml_host, xpath))
}


#' Get all the IPs in a report
#'
#' @param doc 
#'
#' @return
#' @export
#'
#' @examples
GetAllIPs <- function(doc) {
  xpath <- paste("//Report/ReportHost/@name", sep = "")
  return(as.character(XML::xpathApply(doc, xpath)))
}

#' Get the open ports of a given IP in a report
#'
#' @param doc 
#' @param ip
#'
#' @return
#' @export
#'
#' @examples
#' sapply(GetAllIPs(doc),function(x) GetAllPortsByIP(doc,x))
#' 
GetAllPortsByIP <- function(doc, ip) {
  xpath <- paste("//Report/ReportHost[@name='", ip, "']/ReportItem/@port", sep = "")
  return(as.character(XML::xpathApply(doc, xpath)))
}

#' Get the protocol of the vulnerabilities of a given IP in a report
#'
#' @param doc 
#' @param ip
#'
#' @return
#' @export
#'
#' @examples
#' 
GetAllprotocolByIP <- function(doc, ip) {
  xpath <- paste("//Report/ReportHost[@name='", ip, "']/ReportItem/@protocol", sep = "")
  return(as.character(XML::xpathApply(doc, xpath)))
}

#' Get the severities of the vulnerabilities of a given IP in a report
#'
#' @param doc 
#' @param ip
#'
#' @return
#' @export
#'
#' @examples
#' sapply(GetAllIPs(doc),function(x) GetAllSeveritiesByIP(doc,x))
#' 
GetAllSeveritiesByIP <- function(doc, ip) {
  xpath <- paste("//Report/ReportHost[@name='", ip, "']/ReportItem/@severity", sep = "")
  return(as.character(XML::xpathApply(doc, xpath)))
}

#' Get the CVS Base Score of the vulnerabilities of a given IP in a report
#'
#' @param doc 
#' @param ip
#'
#' @return
#' @export
#'
#' @examples
#'
#' 
GetCVSBaseByIP <- function(doc, ip) {
  xpath <- paste("//Report/ReportHost[@name='", ip, "']/ReportItem/cvss_base_score", sep = "")
  return(sapply(XML::xpathApply(doc, xpath), xmlValue))
}

#' Get the CWEs of a given IP in a report
#'
#' @param doc 
#' @param ip
#'
#' @return
#' @export
#'
#' @examples
#'
#' 
GetCWEByIP <- function(doc, ip) {
  xpath <- paste("//Report/ReportHost[@name='", ip, "']/ReportItem/cwe", sep = "")
  return(sapply(XML::xpathApply(doc, xpath), xmlValue))
}

#' Get the CVEs of a given IP in a report
#'
#' @param doc 
#' @param ip
#'
#' @return
#' @export
#'
#' @examples
#'
#' 
GetCVEByIP <- function(doc, ip) {
  xpath <- paste("//Report/ReportHost[@name='", ip, "']/ReportItem/cve", sep = "")
  return(sapply(XML::xpathApply(doc, xpath), xmlValue))
}
