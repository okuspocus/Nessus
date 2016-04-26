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
  data_frame[,"IP"] <- as.character(data_frame[,"IP"])
  data_frame <- data.frame(cbind(data_frame, CVE = as.character("")), stringsAsFactors = FALSE)
  data_frame[,"CVE"] <- as.character(data_frame[,"CVE"])
  
  df.cves <- data.frame(CVEs = as.character(), stringsAsFactors = FALSE)
  for (i in 1:nrow(data_frame_aux)) {
    port <- data_frame_aux[i, c("port")]
    protocol <- data_frame_aux[i, c("protocol")]
    pluginID <- data_frame_aux[i, c("pluginID")]
    xpath <- paste("//ReportHost[@name='", ip,
                   "']/ReportItem[@port='", port,
                   "' and @protocol='", protocol,
                   "' and @pluginID='", pluginID,
                   "']/cve", sep = "")
    df.cves <- data.frame(CVEs = sapply(XML::xpathApply(doc, xpath), unlist(XML::xmlValue)), stringsAsFactors = FALSE)
    #tempo <- cbind(IP = ip,
    #               port = as.character(port),
    #               protocol = as.character(protocol),
    #               pluginID = as.character(pluginID),
    #               CVEs = as.vector(df.cves[['CVEs']]))
    if (nrow(df.cves) == 0) {
      #data_frame <- as.data.frame(cbind(data_frame[i], as.vector("")), stringsAsFactors = FALSE)
    }
    else {
      data_frame[i, "CVE"] <- as.character(paste(as.character(df.cves[['CVEs']]), collapse = ", "))
    }
  }
  
  df_global <- as.data.frame(rbind(df_global, data_frame))
}

