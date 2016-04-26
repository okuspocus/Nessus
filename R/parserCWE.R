library(XML)

#' Downloads the CWE global zip file
#'
#' @return
#' @export
#'
#' @examples
UpdateCWEData <- function() {
  download.file(url = "https://cwe.mitre.org/data/xml/views/2000.xml.zip",
                destfile = "sampe-CWE/2000.xml.zip")
}

#' Returns the content of the CWE xml document
#'
#' @return
#' @export
#'
#' @examples
GetRawCWEData <- function() {
  return(XML::xmlParse(unzip("sampe-CWE/2000.xml.zip")))
}

#' Returns the title of a given CWE
#'
#' @param doc 
#' @param cwe 
#'
#' @return
#' @export
#'
#' @examples
GetCWETitle <- function(doc, cwe = "1") {
  xpath <- paste("//Weakness[@ID = '", cwe, "']/@Name", sep = "")
  return(unlist(XML::xpathApply(doc, xpath))[["Name"]])
}

#' Returns the children nodes of a given CWE
#'
#' @param doc 
#' @param cwe 
#'
#' @return
#' @export
#'
#' @examples
GetCWEChildrenNodes <- function(doc, cwe = "1") {
  xpath <- paste("//Weakness[Relationships/Relationship/Relationship_Target_ID = '",
                 cwe, 
                 "' and Relationships/Relationship/Relationship_Nature = 'ChildOf'",
                 " and Relationships/Relationship/Relationship_Target_Form = 'Weakness']",
                 sep = "")
  return(XML::xpathApply(doc, xpath))
}

#' Get the children IDs of a given CWE
#'
#' @param doc 
#' @param cwe 
#'
#' @return
#' @export
#'
#' @examples
GetCWEChildrenIDs <- function(doc, cwe = "1") {
  xpath <- paste("//Weakness[Relationships/Relationship/Relationship_Target_ID = '",
                 cwe,
                 "' and ",
                 " Relationships/Relationship/Relationship_Nature = 'ChildOf'",
                 " and ",
                 "Relationships/Relationship/Relationship_Target_Form = 'Weakness']/@ID",
                 sep = "")
  return(as.character(XML::xpathApply(doc, xpath)))
}

#' Get ALL the children IDs of a given CWE
#'
#' @param doc 
#' @param cwe 
#'
#' @return
#' @export
#'
#' @examples
GetAllCWEChildrenIDs <- function(doc, cwe = "1") {
  childs <- GetCWEChildrenIDs(doc, cwe)
  
  if (identical(childs, character(0))) {
    return(cwe)
  } else {
    return(unique(c(cwe, unlist(lapply(childs, function(x) GetAllCWEChildrenIDs(doc, x))))))
  }
}
