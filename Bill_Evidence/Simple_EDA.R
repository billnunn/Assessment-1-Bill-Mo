setwd('/Users/willnunn/Desktop/DST')

library(dplyr)
library(ggplot2)

df <- read.csv("kddcup.data_10_percent", header = FALSE)
head(df)

# Sort out the column labels and stick them on.
labs <- read.csv("kddcup.names.txt")[ , 1]
labs <- c(labs, 'connection_type: symbolic')
colnames(df) <- labs
head(df)

table(df$`connection_type: symbolic`)

# We see that some of the connection types are very infrequent, spy., phf.,
# perl., multihop. all occur fewer than 10 times. We therefore categorise
# the attack types.

# First get rid of the irritating dots at the end of the connection types.
for(i in unique(df$`connection_type: symbolic`)){
  df <- df %>%
    mutate(`connection_type: symbolic` = 
             replace(`connection_type: symbolic`,
                     `connection_type: symbolic` == i,
                      substr(i, 1, nchar(i) - 1)))
}
rm(i)

# Check removal of the dots in the connection_type column has worked
unique(df$`connection_type: symbolic`)

# We have downloaded a table of the attack categories.
cats <- read.table("training_attack_types.txt", header = FALSE)
# Append the normal traffic with "-" to indicate not an attack type.
cats <- rbind(cats, c("normal", "-"))
# Change the row names to the connection_type.
row.names(cats) <- cats[,1]
cats = subset(cats, select = V2)

# It's now easy to add this column with mutate.
df <- df %>% mutate(`attack_category: symbolic` = 
                    cats[`connection_type: symbolic`,])
labs <- c(labs, 'attack_category: symbolic')
rm(cats)

# Looks like eveything has worked well:
table(df[,42:43])
table(df[,43])

# Let's do some EDA to get our heads around the cleaned up data set.

# Cts variables e.g. duration.
duration <- log(1 + df$`duration: continuous.`)
duration <- duration[duration != 0]
boxplot(duration, main = "Log scaled boxplot of non-zero durations.",
        horizontal = TRUE)
rm(duration)

for(i in unique(df$`attack_category: symbolic`)){
  df1 <- df[which(df$`attack_category: symbolic` == i),]
  duration <- log(1 + df1$`duration: continuous.`)
  duration <- duration[duration != 0]
  boxplot(duration, main = i,
          horizontal = TRUE)
}
rm(duration, i, df1)

# Discrete variables e.g. protocol type.
table(df$`protocol_type: symbolic.`)

for(i in unique(df$`attack_category: symbolic`)){
  df1 <- df[which(df$`attack_category: symbolic` == i),]
  print(i)
  print(table(df1$`protocol_type: symbolic.`))
}
rm(i, df1)

# Etc

# I now want to restrict to cts variables only and run a PCA.
# Excited to see how this data behaves.

# Get the cts variables (made easy by the data type being in column names)
cts <- c()
for(i in labs){
  if(grepl("continuous", i, fixed = TRUE)){
    cts <- c(cts, i)
  }
}
rm(i)

# May as well get the symbolic variables too
syms <- c()
for(i in labs){
  if(grepl("symbolic", i, fixed = TRUE)){
    syms <- c(syms, i)
  }
}
rm(i)

df_cts <- df[,cts]

summary(df_cts)

df_syms <- df[,syms]

for(i in 1:7){
  print(table(df_syms[,i]))
}
rm(i)

table(df_syms$`is_host_login: symbolic.`)

# We see num_outbound_cmds: continuous. is uniformly 0, we remove this
cts <- cts[cts != "num_outbound_cmds: continuous."]
df_cts <- df[,cts]

# We see that is_host_login: symbolic. is uniformly 0, we remove this
syms <- syms[syms != "is_host_login: symbolic."]
df_syms <- df[,syms]

# Now let's try a PCA on the cts variables.

test_pca <- prcomp(df_cts, scale = TRUE)
plot(test_pca, type = "l", main = "Variance Explained
     per Principle Component")
df_cts <- cbind(df_cts, test_pca$x)
df_cts <- cbind(df_cts, df$`attack_category: symbolic`)
colnames(df_cts)[67] <- "Category"

set.seed(13)
df_cts_sample <- df_cts[sample(nrow(df_cts), 300),]

ggplot(df_cts_sample, aes(PC1, PC2, col = Category, fill = Category)) +
  geom_point(shape = 21, col = "black")

rm(df_cts_sample)

# We see OK separation of the dos and probe from the normal traffic!
# Let's see if the other attack types are separated.
# The third and fourth principle component are very comparable in size
# To the second.

# We first make a more careful sample, containing 50 instances of each
# attack category and 300 instances of normal traffic.

df_normal <- df_cts[which(df_cts$Category == "-"),]
df_dos <- df_cts[which(df_cts$Category == "dos"),]
df_probe <- df_cts[which(df_cts$Category == "probe"),]
df_r2l <- df_cts[which(df_cts$Category == "r2l"),]
df_u2r <- df_cts[which(df_cts$Category == "u2r"),]

df_normal_sample <- df_normal[sample(nrow(df_normal), 300),]
df_dos_sample <- df_dos[sample(nrow(df_dos), 50),]
df_probe_sample <- df_probe[sample(nrow(df_probe), 50),]
df_r2l_sample <- df_r2l[sample(nrow(df_r2l), 50),]
df_u2r_sample <- df_u2r[sample(nrow(df_u2r), 50),]

sample <- rbind(df_normal_sample, df_dos_sample, df_probe_sample,
                df_r2l_sample, df_u2r_sample)

ggplot(sample, aes(PC1, PC2, col = Category, fill = Category)) +
  geom_point(shape = 21, col = "black")

# After some investigative plotting I found that the the first 
# 25 ish components look to be the useful ones.

rm(test_pca)

# Now I'd like to make some tables to investigate the
# independence between the categorical variables and the attack
# types.

# Protocol type.
test <- prop.table(table(df_syms$`protocol_type: symbolic.`, 
      df_syms$`attack_category: symbolic`), margin = 2)
test
barplot(test, main = "Protocol Type")

# Service.
table(df_syms$`service: symbolic.`,df_syms$`attack_category: symbolic`)

# Flag.
table(df_syms$`flag: symbolic.`,df_syms$`attack_category: symbolic`)

# Land.
table(df_syms$`land: symbolic.`,df_syms$`connection_type: symbolic`)
# Just tells us if attack is a land, a type of dos attack

# Logged in.
table(df_syms$`logged_in: symbolic.`,df_syms$`attack_category: symbolic`)

# Guest login.
test <- prop.table(table(df_syms$`is_guest_login: symbolic.`, 
                         df_syms$`attack_category: symbolic`), margin = 2)
test
barplot(test, main = "Protocol Type")
# We see a fair proportion of r2l attacks are on a guest login.
table(df_syms$`is_guest_login: symbolic.`,df_syms$`connection_type: symbolic`)
# Looks like the warezclient attacks.



