
portsPlot <- function(input_data){
  input_data <- table(input_data,dnn = NULL)
  colors <- c("firebrick1", "gold", "seagreen2", "dodgerblue3", "darkorange", "hotpink", "cadetblue2")
  pie(input_data, main="Port Vulneravility Distribution", col=colors)
  print(input_data)
}

vulnsByIp <- function(input_data){
  input_data <- table(input_data,dnn = NULL)
  colors <- c("firebrick1", "gold", "seagreen2", "dodgerblue3", "darkorange", "hotpink", "cadetblue2")
  barplot(input_data, main="Vulnerability Distribution By IP", col=colors,ylab="count", xlab = "host")
  print(input_data)
}

severityDist <- function(input_data){
  input_data <- table(floor(as.numeric(input_data)),dnn = NULL)
  paleta <- colorRampPalette(c("yellow","red"))
  colors <- paleta(5)
  barplot(input_data, main="Vulnerability Severity Distribution", col=colors,ylab="count", xlab = "severity", )
  print(input_data)
}

cvssDist <- function(input_data){
  input_data <- table(floor(as.numeric(input_data)),dnn = NULL)
  paleta <- colorRampPalette(c("yellow","red"))
  colors <- paleta(10)
  barplot(input_data, main="Vulnerability Severity Distribution", col=colors,ylab="count", xlab = "severity", )
  print(input_data)
}

cwePlot <- function(input_data){
  input_data <- table(input_data,dnn = NULL)
  colors <- c("firebrick1", "gold", "seagreen2", "dodgerblue3", "darkorange", "hotpink", "cadetblue2")
  barplot(input_data, main="CWE distribution", col=colors,ylab="count", xlab = "CWE")
  print(input_data)
}

cvePlot <- function(input_data){
  input_data <- table(input_data,dnn = NULL)
  colors <- c("firebrick1", "gold", "seagreen2", "dodgerblue3", "darkorange", "hotpink", "cadetblue2")
  barplot(input_data, main="CVE distribution", col=colors,ylab="count", xlab = "CVE")
  print(input_data)
}










