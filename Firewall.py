
import csv

#Node data structure for each node in the Trie
class Node(object):

    def __init__(self,start,end,port,direction,protocol):
        self.map = dict()
        self.port_map = dict()
        self.directions = set()
        self.protocols = set()

        self.start = start
        self.end = end

        #Add the port to the node
        self.add_port(port)
        self.add_protocol(protocol)
        self.add_direction(direction)

    #Function to add a child node and return it
    def add_child(self,start,end,port,direction,protocol):

        node = Node(start,end,port,direction,protocol)
        self.map[(start,end)] = node
        return node

    #Function to add port to the node
    def add_port(self,port):
        # Add to port_map
        if '-' in port:
            port_split = port.split('-')
            self.port_map[int(port_split[0])] = int(port_split[1])
        else:
            self.port_map[int(port)] = int(port)

    # Function to add protocol to the node
    def add_protocol(self,protocol):
        self.protocols.add(protocol)

    # Function to add direction to the node
    def add_direction(self,direction):
        self.directions.add(direction)

#Trie data structure
class Trie(object):

    def __init__(self):
        #Dummy root node
        self.root = Node("0","0","0","0","0")

    #Function to add rules to the Trie
    def add_rule(self,rule):

        #split_rule = rule.split(',')
        ip,protocol,direction,port = rule[3], rule[1], rule[0], rule[2]

        start = ip.split(".")
        end = ip.split(".")
        #Range of ip's
        if '-' in ip:
            start = ip.split('-')[0].split(".")
            end = ip.split('-')[1].split(".")

        root = self.root
        for index in range(4):

            first = start[index]
            second = end[index]

            if (first,second) in root.map:
                node = root.map[(first,second)]
                #Update the parameters in the current node
                node.add_port(port)
                node.add_protocol(protocol)
                node.add_direction(direction)
                root = node
            else:
                root = root.add_child(first,second,port,direction,protocol)

    #Function to check if port is present below the node
    def check_port(self,node,port):
        map = node.port_map
        for key in map:
            if port == key or (port>=key and port<=map[key]):
                return True
        return False

    # Function to check if protocol is present below the node
    def check_protocol(self,node,protocol):
        return protocol in node.protocols

    # Function to check if direction is present below the node
    def check_direction(self,node,direction):
        return direction in node.directions

    #function to test a packet for acceptance
    def test_packet(self,direction,protocol,port,ip_address):
        octets = ip_address.split(".")
        return self.test_packet_helper(self.root,octets,0,direction,protocol,str(port),0)

    # Helper function to test the packet for acceptance
    def test_packet_helper(self, root, octets, index, direction, protocol, port, flag):

        #Base condition
        if index == len(octets):
            return True

        #Used flag to check when the later octets are less but the previos ones are bigger
        #Eg: start:192.0.0.0 and end:200.0.0.0
        #To check if 192.200.200.100 lies between them
        # flag = 0
        if root.end > root.start:
            flag = 1

        #Get the matches for current octet
        matches = self.get_matches(root, octets[index], flag)
        # print root.map
        # print octets[index], matches
        # print flag
        # print "\n"
        for match in matches:
            if not self.check_port(root.map[match], int(port)) or \
                    not self.check_direction(root.map[match], direction) or \
                    not self.check_protocol(root.map[match], protocol):
                continue

            # print octets[index], match
            # print "\n"

            #Recursive call for checkign further octets
            ret = self.test_packet_helper(root.map[match], octets, index + 1, direction, protocol, port, flag)
            if ret == True:
                return ret

        return False

    #Function to get all matching keys based on the octet
    def get_matches(self,root,octet,flag):

        ret = []
        for key in root.map:
            if key == octet:
                ret.append(key)
            if int(octet) >= int(key[0]) and int(octet) <= int(key[1]):
                ret.append(key)
            else:
                if flag == 1:
                    ret.append(key)
        return ret

#Main Firewall class
class Firewall(object):

    def __init__(self,path):
        self.file_path = path
        self.firewall_rules = Trie()

    #Function to read the file and add the rules to a Trie
    def read_file(self):
        path = self.file_path
        if len(path)==0:
            raise Exception("Path is empty")

        with open(path) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                self.firewall_rules.add_rule(row)

        #hardcoded rules
        # rules = ['inbound','tcp','80','192.168.1.2',
        #          'outbound','tcp','10000-65535','100.50.0.0-200.100.100.100',
        #          'inbound','udp','53','192.168.1.1-192.168.2.5',
        #          'outbound','udp','1000-2000,52.12.48.92',
        #          'outbound','udp','500-10000','0.0.0.0-255.255.255.255']

        #for rule in rules:
         #   self.firewall_rules.add_rule(rule)

    #Function to check for acceptance of a packet
    def accept_packet(self,direction,protocol,port,ip_address):
        return self.firewall_rules.test_packet(direction,protocol,port,ip_address)
