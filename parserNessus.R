library(XML)

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

#' Get the global data frame of a Nessus report
#'
#' @param doc 
#'
#' @return
#' @export
#'
#' @examples
GetGlobalDataFrame <- function(doc) {
  IPs <- GetAllIPs(doc)
  
  df_global <- data.frame(col1 = as.character(),
                          col2 = as.character(),
                          col3 = as.character(),
                          col4 = as.character(),
                          col5 = as.character(),
                          col6 = as.character(),
                          col7 = as.character(),
                          col8 = as.character(),
                          col9 = as.character(),
                          col9 = as.character(),
                          stringsAsFactors = FALSE)
  
  for (ip in IPs) {
    xpath <- paste("//ReportHost[@name='", ip, "']/ReportItem", sep = "")
    data_frame_aux <- data.frame(t(sapply(XML::xpathApply(doc, xpath),
                                          unlist(XML::xmlAttrs))),
                                 stringsAsFactors = FALSE) #Get all the attrs
    data_frame_aux$svc_name <- NULL #Delete the svc_name attribute
    data_frame <- data.frame(cbind(IP = as.character(ip), data_frame_aux), stringsAsFactors = FALSE)
    data_frame[,"IP"] <- as.character(data_frame[,"IP"])    #Convert the IP column to srting
    data_frame <- data.frame(cbind(data_frame, CVE = as.character("")), stringsAsFactors = FALSE)
    data_frame[,"CVE"] <- as.character(data_frame[,"CVE"])  #Convert the CVE column to string
    data_frame <- data.frame(cbind(data_frame, CWE = as.character("")), stringsAsFactors = FALSE)
    data_frame[,"CWE"] <- as.character(data_frame[,"CWE"])  #Convert the CWE column to string
    data_frame <- data.frame(cbind(data_frame, CVSS_Base = as.character("")), stringsAsFactors = FALSE)
    data_frame[,"CVSS_Base"] <- as.character(data_frame[,"CVSS_Base"])  #Convert the CVSS_Base column to string
    
    #Initialize and fill the df.cves dataframe
    df.cves <- data.frame(CVEs = as.character(), stringsAsFactors = FALSE)
    df.cwes <- data.frame(CWEs = as.character(), stringsAsFactors = FALSE)
    for (i in 1:nrow(data_frame_aux)) {
      port <- data_frame_aux[i, c("port")]          #Get the port
      protocol <- data_frame_aux[i, c("protocol")]  #Get the protocol
      pluginID <- data_frame_aux[i, c("pluginID")]  #Get the pluginID
      
      xpath_cves <- paste("//ReportHost[@name='", ip,
                          "']/ReportItem[@port='", port,
                          "' and @protocol='", protocol,
                          "' and @pluginID='", pluginID,
                          "']/cve", sep = "")
      
      df.cves <- data.frame(CVEs = sapply(XML::xpathApply(doc, xpath_cves),
                                          unlist(XML::xmlValue)),
                            stringsAsFactors = FALSE)
      
      if (nrow(df.cves) != 0) {
        data_frame[i, "CVE"] <- as.character(paste(as.character(df.cves[['CVEs']]),
                                                   collapse = ", "))
      }
      
      xpath_cwes <- paste("//ReportHost[@name='", ip,
                          "']/ReportItem[@port='", port,
                          "' and @protocol='", protocol,
                          "' and @pluginID='", pluginID,
                          "']/cwe", sep = "")
      
      df.cwes <- data.frame(CWEs = sapply(XML::xpathApply(doc, xpath_cwes),
                                          unlist(XML::xmlValue)),
                            stringsAsFactors = FALSE)
      if (nrow(df.cwes) != 0) {
        data_frame[i, "CWE"] <- as.character(paste(as.character(df.cwes[['CWEs']]),
                                                   collapse = ", "))
      }
      
      xpath_cvss <- paste("//ReportHost[@name='", ip,
                          "']/ReportItem[@port='", port,
                          "' and @protocol='", protocol,
                          "' and @pluginID='", pluginID,
                          "']/cvss_base_score", sep = "")
      
      df.cvss <- data.frame(CVSS_Base = sapply(XML::xpathApply(doc, xpath_cvss),
                                          unlist(XML::xmlValue)),
                            stringsAsFactors = FALSE)
      if (nrow(df.cvss) != 0) {
        data_frame[i, "CVSS_Base"] <- as.character(paste(as.character(df.cvss[['CVSS_Base']]),
                                                   collapse = ", "))
      }
      
    }
    
    df_global <- as.data.frame(rbind(df_global, data_frame))
  }
  
  return(df_global)
}
