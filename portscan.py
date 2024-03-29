# Classes for the greppable Nmap port scan results

class Port:
    def __init__(self, portInfoString):
        items = portInfoString.split("/")
        items = [item.strip() for item in items]

        self.port = items[0]
        self.status = items[1]
        self.protocol = items[2]
        self.service = items[4]
        self.version = items[6]

    def __str__(self):
        return f"{self.port} {self.status} {self.protocol} {self.service} {self.version}"




class PortScan:
    def __init__(self, input):
        self.ports = []
        port_items = input.split(",")
        for item in port_items:
            self.ports.append(Port(item))

    def __str__(self):
        output = "" 
        
        for port in self.ports:
            output += f"{str(port)}\n"
        
        return output
