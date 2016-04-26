
portsPlot <- function(input_data){
  print(table(as.character(input_data)))
  colors <- c("firebrick1", "gold", "seagreen2", "dodgerblue3", "darkorange", "hotpink", "cadetblue2")
  pie(table(input_data), main="Port Vulneravility Distribution", col=colors)
}

vulnsByIp <- function(input_data){
  colors <- c("firebrick1", "gold", "seagreen2", "dodgerblue3", "darkorange", "hotpink", "cadetblue2")
  barplot(table(input_data), main="Vulnerability Distribution By IP", col=colors,ylab="count", xlab = "severity")
}

severityDist <- function(input_data){
  input_data <- floor(as.numeric(input_data))
  paleta <- colorRampPalette(c("yellow","red"))
  colors <- paleta(10)
  barplot(table(input_data), main="Vulnerability Severity Distribution", col=colors,ylab="count", xlab = "severity", )
}
