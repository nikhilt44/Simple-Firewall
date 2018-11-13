
from Firewall import Firewall

#Define the path for rules
path = "rules.csv"

#Contents of csv file
# inbound,tcp,80,192.168.1.2
# outbound,udp,5300,192.200.0.0-200.0.0.0
# outbound,tcp,10000-20000,192.168.10.11
# inbound,udp,53,192.168.1.1-192.168.2.5
# outbound,udp,1000-2000,52.12.48.92
# outbound,tcp,20000-65535,102.100.0.254
# outbound,tcp,0-34000,0.0.0.0-255.255.255.255
# inbound,udp,500,12.11.30.181
# outbound,tcp,2000-2500,0.12.30.1-255.12.30.255


#Create a Firewall and add the rules from the file
# firewall = Firewall("")
# firewall.read_file()

firewall = Firewall(path)
firewall.read_file()

#firewall.accept_packet("inbound", "udp", 53, "192.168.2.1")

#Tests
assert (firewall.accept_packet("inbound", "udp", 53, "192.168.2.1") == True)
assert (firewall.accept_packet("outbound", "udp", 53, "192.168.2.1") == False)
assert (firewall.accept_packet("outbound", "udp", 5300, "192.168.255.255") == True)
assert (firewall.accept_packet("inbound", "udp", 500, "12.11.30.181") == True)
assert (firewall.accept_packet("outbound", "tcp", 100, "200.200.200.200") == True)
assert (firewall.accept_packet("outbound", "udp", 100, "200.200.200.200") == False)