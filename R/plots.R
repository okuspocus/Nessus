
portsPlot <- function(input_data){
  input_data <- input_data[ input_data != 0 ]
  print(table(input_data))
  colors <- c("firebrick1", "gold", "seagreen2", "dodgerblue3", "darkorange", "hotpink", "cadetblue2")
  pie(table(input_data), main="Port Vulneravility Distribution", col=colors)
}

vulnsByIp <- function(input_data){
  barplot(table(input_data), main="Vulnerability Distribution By IP", col=colors,ylab="count", xlab = "severity")
}

severityDist <- function(input_data){
  input_data <- floor(as.numeric(input_data))
  colnames<-c('0','1','2','3', '4', '5', '6', '7','8','9','10')
  paleta <- colorRampPalette(c("yellow","red"))
  colors <- paleta(10)
  barplot(table(input_data), main="Vulnerability Severity Distribution", col=colors,ylab="count", xlab = "severity")
}
