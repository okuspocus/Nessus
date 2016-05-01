
portsPlot <- function(input_data){
  input_data <- table(input_data)
  print(input_data)
  colors <- c("firebrick1", "gold", "seagreen2", "dodgerblue3", "darkorange", "hotpink", "cadetblue2")
  pie(input_data, main="Port Vulneravility Distribution", col=colors)
}

vulnsByIp <- function(input_data){
  input_data <- table(input_data)
  print(input_data)
  colors <- c("firebrick1", "gold", "seagreen2", "dodgerblue3", "darkorange", "hotpink", "cadetblue2")
  barplot(input_data, main="Vulnerability Distribution By IP", col=colors,ylab="count", xlab = "host")
}

severityDist <- function(input_data){
  input_data <- table(floor(as.numeric(input_data)))
  print(input_data)
  paleta <- colorRampPalette(c("yellow","red"))
  colors <- paleta(10)
  barplot(input_data, main="Vulnerability Severity Distribution", col=colors,ylab="count", xlab = "severity", )
}
