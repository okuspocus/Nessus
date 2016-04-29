library(Nessus)

doc <- XML::xmlParseDoc(file = "sample-scans/625.xml")

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
    
    df.cves <- data.frame(CVEs = sapply(XML::xpathApply(doc, xpath_cves), unlist(XML::xmlValue)), stringsAsFactors = FALSE)
    
    if (nrow(df.cves) != 0) {
      data_frame[i, "CVE"] <- as.character(paste(as.character(df.cves[['CVEs']]), collapse = ", "))
    }
    
    xpath_cwes <- paste("//ReportHost[@name='", ip,
                        "']/ReportItem[@port='", port,
                        "' and @protocol='", protocol,
                        "' and @pluginID='", pluginID,
                        "']/cwe", sep = "")
    
    df.cwes <- data.frame(CWEs = sapply(XML::xpathApply(doc, xpath_cwes), unlist(XML::xmlValue)), stringsAsFactors = FALSE)
    if (nrow(df.cwes) != 0) {
      data_frame[i, "CWE"] <- as.character(paste(as.character(df.cwes[['CWEs']]), collapse = ", "))
    }
    
  }
  
  df_global <- as.data.frame(rbind(df_global, data_frame))
}

