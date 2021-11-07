path <- '/Users/willnunn/Desktop/DST'

setwd(path)
rm(path)

library(dplyr)

df <- read.csv("kddcup.data_10_percent", header = FALSE)
labs <- read.csv("kddcup.names.txt")[ , 1]
cats <- read.table("training_attack_types.txt", header = FALSE)

# Remove dots from labels and add column names.
for(i in 1:41){
  labs[i] = substr(labs[i], 1, nchar(labs[i]) - 1)
}
rm(i)
labs <- c(labs, 'connection_type: symbolic')
colnames(df) <- labs

# Remove dots from connection types.
for(i in unique(df$`connection_type: symbolic`)){
  df <- df %>%
    mutate(`connection_type: symbolic` = 
             replace(`connection_type: symbolic`,
                     `connection_type: symbolic` == i,
                     substr(i, 1, nchar(i) - 1)))
}
rm(i)

# Add attack_types column.
cats <- rbind(cats, c("normal", "benign"))
row.names(cats) <- cats[,1]
cats = subset(cats, select = V2)
df <- df %>% mutate(`attack_type: symbolic` = 
                      cats[`connection_type: symbolic`,])

# Add is_normal column.
df <- df %>% 
      mutate(`is_normal: symbolic` =
             case_when(`attack_type: symbolic` == "benign" ~ 1,
                       `attack_type: symbolic` != "benign" ~ 0))

# Update labels
labs <- c(labs, "attack_type: symbolic", "is_normal: symbolic")

# Remove the variables which are uniformly zero
labs <- labs[labs != "num_outbound_cmds: continuous"]
labs <- labs[labs != "is_host_login: symbolic"]
df <- df[,labs]
rm(labs, cats)

df$`is_normal: symbolic` <- as.factor(df$`is_normal: symbolic`)

# This is weird but sorts out the column names!
df <- data.frame(df)

# Great this is the prepared data set.

# I now want to write some useful functions to help
# construct sensible training and test sets.

set.seed(3111)


stratified_new_test <- function(new_attacks, percent) {
  x <- c()
  for(i in new_attacks){
    x <- c(x, 
           rownames(df[which(df$`connection_type..symbolic` == i),]))
  }
  y <- setdiff(unique(df$`connection_type..symbolic`), new_attacks)
  for(i in y){
    n <- rownames(df[which(df$`connection_type..symbolic` == i),])
    x <- c(x, sample(n, as.integer(length(n) * (percent / 100) +1),
                     replace = FALSE))
  }
  return(x)
}


train_given_test <- function(test_set) {
  x <- rownames(df) %>% setdiff(test_set)
  return(x)
}


# Now let's run a random forest classifier.

library(randomForest)

test_rows <- stratified_new_test(c(), 20)
train_rows <- train_given_test(test_rows)

train <- data.frame(df[train_rows, -c(40,41)])
test <- data.frame(df[test_rows, -c(40,41)])

rf <- randomForest(`is_normal..symbolic`~., data = train, ntree = 30)

p_train <- predict(rf, train)
p_test <- predict(rf, test)

plot(rf, main = "OOB Error against number of trees")

acc_test <- data.frame(cbind(p_test, df[test_rows,40]))

acc_test <- as.matrix(table(acc_test))

acc <- c()
counts <- c()
for(i in 1:ncol(acc_test)) {
  acc <- c(acc, round(acc_test[1,i] / (acc_test[1,i] + acc_test[2,i]),5))
  counts <- c(counts, acc_test[1,i] + acc_test[2,i])
}
rm(i)

acc_test <- rbind(acc_test, rbind(acc, counts))
rm(acc,counts)
acc_test[3, "normal"] = 1 - acc_test[3, "normal"]
acc_test <- acc_test[3:4,]
print("[<-"(acc_test, as.character(acc_test)), quote = FALSE)

rm(rf, test_rows, train_rows, test, train, acc_test,
   p_test, p_train)

# Could cross validation to optimise tree depth.

# Performed (I think) impressively well. We now want to investigate
# performance when the train set is not representative of
# the test set i.e. keeping some connection types in the test
# set exclusively.

# (Hopefully it's shit on the new attacks and an anomaly detection
# model can really come into it's own)

table(df[,40:41])

# We withhold "nmap", "pod", "guess_passwd", "buffer_overflow"

test_rows <- stratified_new_test(c("nmap","pod",
                                   "guess_passwd", 
                                   "buffer_overflow"), 20)
train_rows <- train_given_test(test_rows)

train <- data.frame(df[train_rows, -c(40,41)])
test <- data.frame(df[test_rows, -c(40,41)])

rf <- randomForest(`is_normal..symbolic`~., data = train, ntree = 30)

p_train <- predict(rf, train)
p_test <- predict(rf, test)

acc_test <- data.frame(cbind(p_test, df[test_rows,40]))

acc_test <- as.matrix(table(acc_test))

acc <- c()
counts <- c()
for(i in 1:ncol(acc_test)) {
  acc <- c(acc, round(acc_test[1,i] / (acc_test[1,i] + acc_test[2,i]),5))
  counts <- c(counts, acc_test[1,i] + acc_test[2,i])
}
rm(i)

acc_test <- rbind(acc_test, rbind(acc, counts))
rm(acc,counts)
acc_test[3, "normal"] = 1 - acc_test[3, "normal"]
acc_test <- acc_test[3:4,]
print("[<-"(acc_test, as.character(acc_test)), quote = FALSE)

rm(rf, test_rows, train_rows, test, train, acc_test,
   p_test, p_train)

# We see the accuracy on the withheld attacks drops off
# significantly. This is a real problem: we want
# our classifier to pick up on new types of attack!

# To try and detect new types of attack we try out some
# anomaly detection algorithms.

# Suppose we have a set of data we believe is normal (perhaps
# the data which wasn't picked up by our random forest):

library(solitude)

data <- df[which(df$is_normal..symbolic == 1),]

for(i in c("nmap","pod","guess_passwd", "buffer_overflow")){
  data <- rbind(data, df[which(df$connection_type..symbolic == i),])
}
rm(i)

isf <- isolationForest$new()

isf$fit(data[,-c(40,41,42)])

data$prediction <- isf$predict(data)

normal <- c()
nmap <- c()
pod <- c()
guess <- c()
buff <- c()

cutoff_vals <- 0.585+0.0001*1:600

for(j in 0.585+0.0001*1:300){

data$outlier <- as.factor(ifelse(data$pred$anomaly_score >=j,
                                 "outlier", "normal"))

x <- table(data$connection_type..symbolic, data$outlier) %>%
     as.matrix()

acc <- c()
for(i in 1:nrow(x)){
acc <- c(acc, round(x[i,2] / (x[i,1] + x[i,2]),5))
}
rm(i)
x <- cbind(x, acc)
x["normal", 3] = 1 - x["normal", 3]

normal <- c(normal, x["normal", 3])
nmap <- c(nmap, x["nmap", 3])
pod <- c(pod, x["pod", 3])
guess <- c(guess, x["guess_passwd",3])
buff <- c(buff, x["buffer_overflow",3])

}
rm(j,acc,counts,x)

plot(0.585+0.0001*1:300, type = "l", normal, ylim = range(0,1))
lines(0.585+0.0001*1:300, nmap, col = "Red")
lines(0.585+0.0001*1:300, pod, col = "Green")
lines(0.585+0.0001*1:300, guess, col = "Blue")
lines(0.585+0.0001*1:300, buff, col = "Orange")




