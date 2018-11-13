# Simple-Firewall

I have used a Trie to store the rules. Nodes at each level store the corresponding octets(single and range as well). So, basically the tree would have 4 levels. 

At each node I have store the following things
Start and end of ip range (Start and end are same if its a single ip)
Range of ports after this node 
Directions seen after this node
Protocols seen after this node

Following is an example of rules - 

inbound,udp,53,192.168.1.1-200.200.2.5, 
outbound,tcp,110,192.50.2.100-200.100.200.5, 

the tree would be as below,
                                                    0,0,0,0
                                        |
                     192-200,{53,110},{udp,tcp},{inbound,outbound}
                            |                           |
         168-200,{53},{udp},{inbound}               50-100,{110},{tcp},{outbound}
                    |                                      |
           1-2,{53},{udp},{inbound}                 2-200,{110},{tcp},{outbound}
                    |                                      |
           1-5,{53},{udp},{inbound}                 100-5,{110},{tcp},{outbound}
           
           
Link for tree(because its not displayed properly here): https://drive.google.com/file/d/12j78y69cvKMdcSZomiLivfSrGrnCGZnn/view?usp=sharing

Storing port,direction and protocol info at each node helps me make an early decision as to whether I should further traverse the branch in the tree or not.

In the above example, if I get a packet with values - inbound, udp, 200, 192.1.1.1, I will not go into the branch as the packet port number is not present in the node at the first level

This may result in usage of more storage space but might improve the runtime. Anyways, adding rules is one time process. We can prepare the tree once and save it.

I tried to cover as many things as possible in the allotted duration of 1 hour. I also tested it using few examples. Also, I would be further interested in exploring more efficient approaches to this!

Regarding the team preference, I would be most interested in the data team but open to other teams as well.


