"""
CSCI 262 - Systems Security
Assignment 3
Email system event modeller & intrusion detection system

Name: Joen Tai
UOW ID: 7432100
"""
import sys
import argparse
import numpy as np
from scipy.stats import norm

# Adding arugment parser
parser = argparse.ArgumentParser(prog="CSCI262 Assignment 3", description='Email system event modeller & intrusion detection system.')
parser.add_argument("string", nargs=3, type=str, help='Enter "python ids.py <Events>.txt <Stats>.txt <Days>"')
args = parser.parse_args()

# Saving input file to variables
eventFile, statFile, totalDays = sys.argv[1], sys.argv[2], int(sys.argv[3])

# Variables
events = []
stats = []
baseEvents = {}
baseStats = {}
inputstats = []
inputStats = {}

# Functions
# Reading files from inital input
def readFile(filename):
    count = 0
    with open(filename, "r") as f:
        print(f"Reading {filename} file...")
        print("-------------------------------------------------")
        for line in f:
            if count == 0:
                count += 1
            elif filename == "Events.txt":
                events.append(line.strip().split(":"))
                count += 1
            elif filename == "Stats.txt":
                stats.append(line.strip().split(":"))
                count += 1
        
        print(f"{count-1} lines successfully read")
        print("-------------------------------------------------")
        print(f"Storing {filename} file...")
        print("-------------------------------------------------\n")
        
# Checking for inconsistencies between the files
def checkInconsistencies(baseEvents, baseStats):
    boolean = False
    for key in baseEvents.keys():
        if key in baseStats:
            boolean = True
    if boolean == True:        
        print("Files have been verified.\n-------------------------------------------------")

# Storing data to dictionary
def saveToDict(dictionary, listData):
    keys = []
    dictionary = {}
    for row in listData:
        keys.append(row[0])
    # Ensuring data is saved to correct dictionary
    if (listData == events):
        dictionary = dictionary.fromkeys(keys)
        # Adding values to events dictionary
        for i in range(0, 5):
            values = []
            for y in range(1, 5):
                values.append(listData[i][y])
                key = {listData[i][0]: values}
                dictionary.update(key)
        return (dictionary)
    else:
        dictionary = dictionary.fromkeys(keys)
        # Adding values to stats dictionary
        for i in range(0, 5):
            values = []
            for y in range(1, 3):
                values.append(listData[i][y])
                key = {listData[i][0]: values}
                dictionary.update(key)
        return (dictionary)
        
# Printing data stored during inital input
def printDict(dictionary):
    for key, val in dictionary.items():
        if (key == "Logins"):
            print("{} \t\t {}".format(key, val))
        else:
            print("{} \t {}".format(key, val))

# Generating logs based on base statistics
def generateLogs(days, mean, sd, cd):
    # Ensuring continuous events are rounded to 2 decimal places
    if cd.upper() == "C":
        genLog = norm.ppf(np.random.random(days), loc=mean, scale=sd)
        for i in range(len(genLog)):
            genLog[i] = round(genLog[i], 2)
    else:
        genLog = norm.ppf(np.random.random(days), loc=mean, scale=sd).astype(int)
    return (list(genLog))
    
# Checking if mean of generated logs is within ±3 from base statistics
def checkValid(genList, baseVal, eventName):
    sumEvent = 0
    mean = 0
    for i in genList:
        sumEvent += i
    mean = (sumEvent / len(genList))
    print("Checking if generated data is within ± 3 of baseline data",
         "\n-------------------------------------------------")
    if (mean < (baseVal + 3)) or (mean > (baseVal - 3)) or (mean == baseVal):
        print(f"{eventName} is within the acceptable range\n\n")
    else:
        print("Error with generation of events.\n")
        
def generateEventLogs(days, dictionary, baseDict):
    # Generating and checking Logins event
    loginList = generateLogs(days, 
                             int(dictionary["Logins"][0]), 
                             float(dictionary["Logins"][1]), 
                             baseDict["Logins"][0])

    # Generating and checking Time online event
    onlineList = generateLogs(days, 
                              float(dictionary["Time online"][0]), 
                              float(dictionary["Time online"][1]), 
                              baseDict["Time online"][0])

    # Generating and checking Emails sent event
    sentList = generateLogs(days, 
                            int(dictionary["Emails sent"][0]), 
                            float(dictionary["Emails sent"][1]), 
                            baseDict["Emails sent"][0])

    # Generating and checking Emails opened event
    openedList = generateLogs(days, 
                              int(dictionary["Emails opened"][0]), 
                              float(dictionary["Emails opened"][1]), 
                              baseDict["Emails opened"][0])

    # Generating and checking Emails deleted event
    deletedList = generateLogs(days, 
                               int(dictionary["Emails deleted"][0]), 
                               float(dictionary["Emails deleted"][1]), 
                               baseDict["Emails deleted"][0])
    
    return (loginList, onlineList, sentList, openedList, deletedList)

def dailyToDict(days, loginList, onlineList, sentList, openedList, deletedList, arr):
    keys = []
    daylog = {}

    for key, val in arr.items():
        keys.append(key)

    daylog = daylog.fromkeys(keys)

    for i in range(0, days):
        for y in range(1):
            if i == 0:
                key = {stats[i][0]: loginList}
                daylog.update(key)
            elif i == 1:
                key = {stats[i][0]: onlineList}
                daylog.update(key)
            elif i == 2:
                key = {stats[i][0]: sentList}
                daylog.update(key)
            elif i == 3:
                key = {stats[i][0]: openedList}
                daylog.update(key)
            elif i == 4:
                key = {stats[i][0]: deletedList}
                daylog.update(key)
    return (daylog)

# Displays generated logs
def disaplyGenerated(days):
    print("Displaying generated data",
          "\n-------------------------------------------------")

    for i in range(days):
        # Generating each day
        print(f"\n\t\tDay {i + 1}", end='\t')
        # Creating name of file 
        dayFile = "day" + str(i + 1) + ".txt"

        # Logging each day to file
        with open(dayFile, 'w') as f:
            for key, val in daylog.items():
                # Writing logs to file
                f.write("{}:{}\n".format(key, val[i])) # Ensuring it does not goes out of list
                # Displaying daily logs
                if (key == "Logins"):
                    print("\n{} \t\t {}".format(key, val[i]))
                else:
                    print("{} \t {}".format(key, val[i]))
            print("-------------------------------------------------")

    print("\nEvent generation completed",
           "\n-------------------------------------------------")

# Writes generated logs to text file
def writeDayStats(days):
    print("Getting total for each day")
    # Writing totals to file
    with open("Live.txt", 'w') as f:
        for i in range(days):
            # Resets back to 0 and empty for each day
            sd = 0
            mean = 0
            dayVal = []
            dailySum = 0
            # Getting the mean and sd for the different days
            for key, val in daylog.items():
                dailySum += val[i]
                dayVal.append(val[i])
                mean = np.mean(dayVal)
                sd = np.std(dayVal)
            string = f"Day {i + 1} : {dailySum:0.2f} : {mean:0.2f} : {sd:0.2f}"
            if i == 0:
                f.write(string)
            else:
                f.write("\n")
                f.write(string)
            print(string)
        # Calculating total, mean and, standard deviation for each events
        for key, val in daylog.items():
            avg = np.mean(val)
            std = np.std(val)
            sumEvent = sum(val)
            eventString = (f"{key} \t: {sumEvent:0.2f} : {avg:0.2f} : {std:0.2f}")
            if (key == "Logins"):
                f.write("\n\n")
                f.write(eventString)
                print("\n", eventString)
            else:
                f.write("\n")
                f.write(eventString)
                print(eventString)
            
    print("------------------------------------------------- \nAnalysis completed.")

# Reading files from inital input
def readInputFile(filename):
    count = 0
    with open(filename, "r") as f:
        print(f"Reading {filename} file...")
        print("-------------------------------------------------")
        for line in f:
            if count == 0:
                days = int(line)
                count += 1
            else:
                inputstats.append(line.strip().split(":"))
                count += 1
        
        print(f"{count-1} lines successfully read")
        print("-------------------------------------------------")
    return (days)

# Anomaly counter
def getAnomaly(dictionary, arr, days):
    weight = []
    anomaly = []
    # Getting weights in an array
    for i in range(len(arr)):
        for j in range(1):
            weight.append(int(arr[i][4]))

    # Calculating anomaly
    for k in range(days):        
        counter = 0
        for x, (key, val) in enumerate(dictionary.items()):
            counter += abs(((val[k] - np.mean(val)) / np.std(val)) * weight[x])
        anomaly.append(counter)
    return(anomaly)

# Calculating the threshold
def getThreshold(arr):
    count = 0
    for i in range(0, 5):
        for y in range(1):
            count += int(arr[i][4])
    threshold = (count * 2)
    return (threshold)

# Checking if the counter is within the threshold
def alertEngine(threshold, anomaly):
    print(f"Threshold: {threshold} \n")
    for i in range(len(anomaly)):
        if (anomaly[i] > threshold) or (anomaly[i] == threshold):
            print(f'Day {i + 1}: {anomaly[i]:.2f} (FLAGGED)')
        else:
            print(f'Day {i + 1}: {anomaly[i]:.2f} (CLEAR)')

# Calling the functions
# Reading Events.txt
readFile(eventFile)

# Reading Stats.txt 
readFile(statFile)

# Adding events to dictionary
baseEvents = saveToDict(baseEvents, events)

# Adding stats to dictionary
baseStats = saveToDict(baseStats, stats)

# Checking for inconsistencies between the files
checkInconsistencies(baseEvents, baseStats)

print("\nDisplaying data",
      "\n-------------------------------------------------")
printDict(baseEvents)
print("-------------------------------------------------")
printDict(baseStats)
print("-------------------------------------------------", 
      "\n\nBeginning activity engine",
      "\n-------------------------------------------------",
      "\nGenerating and logging events...\n\n")

# Generating event logs
loginList, onlineList, sentList, openedList, deletedList = generateEventLogs(totalDays, baseStats, baseEvents)

# Validating Login event based on mean
checkValid(loginList, int(baseStats["Logins"][0]), events[0][0])

# Validating Time online event based on mean
checkValid(onlineList, float(baseStats["Time online"][0]), events[1][0])

# Validating Emails sent event based on mean
checkValid(sentList, int(baseStats["Emails sent"][0]), events[2][0])

# Validating Emails opened event based on mean
checkValid(openedList, int(baseStats["Emails opened"][0]), events[3][0])

# Validating Emails deleted event based on mean
checkValid(deletedList, int(baseStats["Emails deleted"][0]), events[4][0])

# Saving daily logs to dictionary
daylog = dailyToDict(totalDays, loginList, onlineList, sentList, openedList, deletedList, baseStats)

# Displaying generated data
disaplyGenerated(totalDays)

print("\nBeginning analysis",
     "\n-------------------------------------------------")

# Writing daily statistics total, mean and standard deviation to text file
writeDayStats(totalDays)

print("\n-------------------------------------------------",
      "\nBeginning alert engine.",
      "\n-------------------------------------------------")

# Prompting user to enter new statistic file
while True:
    userInput = input("Please enter new .txt file (or q to quit): ")

    # Checking if user input is valid
    if (userInput.endswith(".txt")):
        # Reading and saving file
        specifiedDays = readInputFile(userInput)
        # Storing file to dictionary
        inputStats = saveToDict(inputStats, inputstats)
        # Generating event logs based on input file
        loginList, onlineList, sentList, openedList, deletedList = generateEventLogs(specifiedDays, inputStats, baseEvents)
        daylog = dailyToDict(specifiedDays, loginList, onlineList, sentList, openedList, deletedList, baseStats)     
        # Displaying generated data
        disaplyGenerated(specifiedDays)
        # Checking anomaly vs threshold
        anomaly = getAnomaly(daylog, events, specifiedDays)
        threshold = getThreshold(events)
        alertEngine(threshold, anomaly)
    # If user enters q, program will stop
    elif (userInput.lower() == "q"):
        sys.exit("Exiting program...")
    else:
        print("Please enter the correct format.")