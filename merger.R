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
                       stringsAsFactors = FALSE)

for (i in IPs) {
  xpath <- paste("//Report/ReportHost[@name='", i, "']/ReportItem", sep = "")
  data_frame_aux <- data.frame(t(sapply(XML::xpathApply(doc, xpath), unlist(XML::xmlAttrs))))
  data_frame_aux$svc_name <- NULL
  data_frame <- as.data.frame(cbind(IP = i, data_frame_aux))
  
  xpath_cve <- paste("//Report/ReportHost[@name='", i, "']/ReportItem/cve", sep = "")
  data_frame_aux2 <- data.frame(sapply(XML::xpathApply(doc, xpath_cve), unlist(XML::xmlValue)))
  
  df_global <- as.data.frame(rbind(df_global, data_frame))
}

