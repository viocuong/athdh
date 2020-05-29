import sys
import json
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
import os
import platform as pf
import argparse
import re

data = []
def UsedOpcode(data):
    Max,Min,Sum= max(data, key=data.get), min(data, key=data.get), len(data)
    res = "Opcode su dung nhieu nhat: "+str(Max)+" "+str(data[Max])+"\nOpcode su dung it nhat: "+str(
        Min)+" "+str(data[Min])+"\nTong so opcode: "+str(Sum)
    return res

def UsedApicall(data):
    Max,Min,Sum = max(data, key=data.get), min(data, key=data.get), len(data)
    res = "Api call su dung nhieu nhat: "+str(Max)+" "+str(data[Max])+"\nApi call su dung it nhat: "+str(
        Min)+" "+str(data[Min])+"\nTong so api call: "+str(Sum)
    return res
def MaxLenString(data):
    Max = 0
    res = ""
    for i in data:
        if(len(i) > Max):
            res = i
            Max = len(i)
    return res


def getDataAnalysis(data):
    filename = data['Pre_static_analysis']['Filename']
    print('File name: '+filename[3:])
    print('Permalink: '+data['VirusTotal'].get('permalink'))
    print('############################################')
    print(UsedOpcode(data['Static_analysis']['Opcodes']))
    print('############################################')
    print(UsedApicall(data['Static_analysis']['API calls']))
    print('############################################')
    print('Chuoi ky tu dai nhat trong doan ma: ' +
          MaxLenString(data['Static_analysis']['Strings']))

####### CHARTING ######################################################################


def charting(data, field):
    datafield = data.get(field)
    x = np.arange(len(datafield))
    labels = []
    height = []

    tup = sorted(datafield.items(), key=lambda v: v[1], reverse=True)
    for i in tup:
        labels.append(i[0])
        height.append(i[1])
    plt.bar(x, height)
    plt.xticks(x, labels, rotation=90)
    plt.subplots_adjust(bottom=0.4)
    plt.xlabel(field, fontweight="bold")
    plt.subplots_adjust(top=1)
    plt.show()

def chartingStrings(data):
    field = "Strings"
    height1 = []
    height2 = []
    labels = []
    barWidth = 0.25
    # sort by len string
    for i in sorted(data.get(field), key=len, reverse=True):
        height1.append(len(i))
        height2.append(data[field].get(i))
        labels.append(i)
    x = np.arange(len(height1))
    x1 = [i+barWidth for i in x]
    plt.bar(x, height1, color='#ff5200', width=barWidth,
            edgecolor='red', label='length')
    plt.bar(x1, height2, color='#00005c', width=barWidth,
            edgecolor='white', label='used')
    plt.xlabel('Used Strings', fontweight='bold')
    plt.xticks([x + barWidth for x in range(len(height2))], labels)
    plt.xticks(x, labels, rotation=90)
    plt.subplots_adjust(bottom=0.4)
    plt.subplots_adjust(top=1)
    plt.show()


def getData():
    global data
    path = Path("Features_files/")
    folder = os.getcwd()+"/Features_files"
    filename = ""
    for file in os.listdir(folder):
        if(re.search("analysis.json$", file)):
            filename = file
            break
    file_to_open = path/filename
    f = open(file_to_open)
    data = json.load(f)

def chartingVT():
    labels = ('detected', 'not detected')
    sizes = []
    detected = notdetected = 0
    explode = [0.1, 0]
    dataVT = data['VirusTotal'].get('scans')
    for i in dataVT:
        if(not dataVT[i].get('detected')):
            notdetected += 1
        else:
            detected += 1
    sizes = [detected, notdetected]
    fig1, ax1 = plt.subplots()
    ax1.pie(sizes, explode=explode, labels=labels,
            autopct='%1.1f%%', shadow=True, startangle=90)
    ax1.axis('equal')
    plt.show()

def Process():
    paser = argparse.ArgumentParser()
    paser.add_argument(
        '-f', '--file', help='File Json, located in the directory Features_file')
    paser.add_argument('-i', '--installenv',
                       help="install necessary modules", action='store_true')
    paser.add_argument(
        '-o', '--opcodes', help='chart opcode', action='store_true')
    paser.add_argument('-vt', '--virustotal',
                       help='pie char virustotal', action='store_true')
    paser.add_argument('-api', '--apicall',
                       help='chart API Call', action='store_true')
    paser.add_argument('-s', '--string', help='chart string',
                       action='store_true')
    args = paser.parse_args()
    flag = 1
    if args.installenv:
        os.system("sudo apt install python3-pip -y")
        os.system("sudo pip3 insatll numpy ")
        os.system("sudo pip3 install matplotlib")
        os.system("sudo pip3 install pandas")
        os.system("sudo pip3 install pathlib")
    else:
        getData()
        getDataAnalysis(data)
        if args.virustotal:
            chartingVT()
        if args.opcodes:
            charting(data['Static_analysis'], 'Opcodes')
        if args.apicall:
            charting(data['Static_analysis'], 'API calls')
        if args.string:
            chartingStrings(data['Static_analysis'])

    # print(args.installenv)
if __name__ == "__main__":
    # getDataAnalysis(data)
    Process()
