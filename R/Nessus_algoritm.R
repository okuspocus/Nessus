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
  xpath <- "//Report/ReportHost"
  return(XML::xpathApply(doc, xpath)[[hostnumber]])
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

#' Get the
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
