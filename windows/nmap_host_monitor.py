# Required Qt5 libraries
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt, QTimer, QProcess

# Required libraries for running nmap and processing data
import subprocess
import re

# Custom class to handle NMAP port scan data
from portscan import *

# Existing UI from Qt Designer ui file
from nhm_mainwindow import Ui_MainWindow

# Set DPI scaling to play nice with Windows (I found this on StackOverflow)
QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True) #enable highdpi scaling
QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True) #use highdpi icons


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # QProcess to run and not block event loop
        self.nmap = None

        # Sets for storing IPs
        self.file_set = set()
        self.scan_set = set()
        self.down_hosts = set()
        self.unknown_hosts = set()
        self.up_hosts = set()

        # Regex queries for processing data
        self.ip_addr_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.(?!0)\d{1,3})') # Regex to pull IP addresses, exclude the network address
        self.scan_ports_pattern = re.compile(r'(?<=Ports:).*/') # Regex to pull the open ports section from the nmap scan

        # Data storage strings
        self.fileHostsString = ""
        self.addressBlock = ""
        self.commandOutput = ""
        self.nmapData = ""

        # Button connections
        self.ui.inputButton.clicked.connect(self.readHostsFile)
        self.ui.ipEnter.clicked.connect(self.getAddressBlock)
        self.ui.scanButton.clicked.connect(self.scanHostStatus)












    def readHostsFile(self):
        fileName, filter = QtWidgets.QFileDialog.getSaveFileName(None, "IP Hosts Text File", None, "(*.txt)")

        self.fileHostsString = ""

        # Read the input hosts file
        with open(fileName, "r") as hosts_file:
            lines = hosts_file.readlines()
            
            for line in lines:
                result = self.ip_addr_pattern.search(line)
                if result != None:
                    self.file_set.add(result[0])

        # Sort the set for easy viewing
        for host in sorted(self.file_set):
            self.fileHostsString += host + "\n"

        self.ui.hostsList.setText(self.fileHostsString)

        self.ui.inputFile.setText("Now using: \n" + fileName)


    def getAddressBlock(self):
        self.addressBlock = self.ui.ipInput.text()
        self.ui.ipPrompt.setText("Current IP Block: \n" + self.addressBlock)


    def scanHostStatus(self):
        self.appendCommandOutput("Scanning " + self.addressBlock)
        self.runNmap(["-n", "-sn", self.addressBlock, "-oG", "-"])

        print(self.nmapData)

        for x in self.nmapData.splitlines():
            result = self.ip_addr_pattern.search(x)
            if result != None:
                self.scan_set.add(result[0])

        self.down_hosts = self.file_set - self.scan_set
        self.unknown_hosts = self.scan_set - self.file_set
        self.up_hosts = self.file_set & self.scan_set

        # Port Scan up hosts
        for host in self.up_hosts:
            self.appendCommandOutput("Scanning up host: " + host)

            self.runNmap(["-T4", "-A", "-Pn", host, "-oG", "-"])

            ports_string = self.scan_ports_pattern.search(self.nmapData)
            if ports_string != None:
                results = PortScan(ports_string[0])
                self.appendCommandOutput(results)
            else:
                self.appendCommandOutput("No open ports detected")
            
            


        # Port Scan down hosts to determine who doesn't respond to pings and who is down
        for host in self.down_hosts:
            self.appendCommandOutput("Scanning possibly down host: " + host)
            self.runNmap(["-T4", "-A", "-Pn", host, "-oG", "-"])

            ports_string = self.scan_ports_pattern.search(self.nmapData)
            if ports_string != None:
                results = PortScan(ports_string[0])
                self.down_hosts.remove(host)
                self.appendCommandOutput(results)
            else:
                self.appendCommandOutput("No open ports detected, host down or unresponsive")
                

    def appendCommandOutput(self, addedCommand):
        self.commandOutput += str(addedCommand) + "\n"
        self.ui.outputBox.setText(self.commandOutput)

    def runNmap(self, arguments):
        if self.nmap == None:
            self.nmap = QProcess()
            self.nmap.readyReadStandardError.connect(self.readStdOutput)
            self.nmap.finished.connect(self.processCleanup)
            self.nmap.start("nmap", arguments)


    def readStdOutput(self):
        self.nmapData = ""
        
        data = self.nmap.readAllStandardOutput()
        output = bytes(data).decode("utf8")
        self.nmapData = output
        self.appendCommandOutput(output)

    def processCleanup(self):
        self.nmap = None






if __name__ == '__main__':
    import sys
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
