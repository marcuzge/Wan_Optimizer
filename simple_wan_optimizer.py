import wan_optimizer
from tcp_packet import Packet
import utils

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into fixed-size blocks.

    This WAN optimizer should implement part 1 of project 4.
    """

    # Size of blocks to store, and send only the hash when the block has been
    # sent previously
    BLOCK_SIZE = 8000

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
        self.flow_to_buffer = {} # buffers need to be flow-specific in order to handle multiple concurrent sources or sources sending data to multiple destinations
        self.cache = {} # cache is global
        return

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 1.  You are welcome to implement private
        helper fuctions that you call here. You should *not* be calling any functions
        or directly accessing any variables in the other middlebox on the other side of 
        the WAN; this WAN optimizer should operate based only on its own local state
        and packets that have been received.
        """
        flow = (packet.src, packet.dest)
        if not flow in self.flow_to_buffer:
            self.flow_to_buffer[flow] = ""
        current_buff = self.flow_to_buffer[flow]

        if packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middlebox, send the packet there.
            if packet.is_raw_data:
                self.send(packet, self.address_to_port[packet.dest])
                empty_space = self.BLOCK_SIZE - len(current_buff)
                if packet.size() < empty_space:
                    self.flow_to_buffer[flow] = current_buff + packet.payload
                else:
                    hash_data = utils.get_hash(current_buff + packet.payload[:empty_space])
                    self.cache[hash_data] = current_buff + packet.payload[:empty_space]
                    self.flow_to_buffer[flow] = packet.payload[empty_space:]    
            # packet already in cache
            else:
                data = self.cache[packet.payload]
                self.packetize_send(flow, packet.is_fin, data, self.address_to_port[packet.dest])

            if packet.is_fin:
                current_buff = self.flow_to_buffer[flow]
                if (len(current_buff) > 0):
                    hash_data = utils.get_hash(current_buff)
                    self.cache[hash_data] = current_buff
                del self.flow_to_buffer[flow]
        #send it across the WAN        
        else: 
            empty_space = self.BLOCK_SIZE - len(current_buff)
            if packet.size() < empty_space:
                self.flow_to_buffer[flow] = current_buff + packet.payload
            else: # buffer is full, send data
                hash_data = utils.get_hash(current_buff + packet.payload[:empty_space])
                if hash_data not in self.cache:
                    self.cache[hash_data] = current_buff + packet.payload[:empty_space]
                    self.packetize_send(flow, False, current_buff + packet.payload[:empty_space], self.wan_port)
                else:
                    self.send(Packet(packet.src, packet.dest, False, False, hash_data), self.wan_port)
                # update buffer
                self.flow_to_buffer[flow] = packet.payload[empty_space:]

            if packet.is_fin:
                source = flow[0]
                destination = flow[1]
                current_buff = self.flow_to_buffer[flow]
                data_hash = utils.get_hash(current_buff)
                if data_hash not in self.cache:
                    if (len(current_buff) > 0):
                        self.cache[data_hash] = current_buff
                    self.packetize_send(flow, True, current_buff, self.wan_port)
                else:
                    hash_packet = Packet(source, destination, False, True, data_hash) #  set is_fin flag
                    self.send(hash_packet, self.wan_port)
                # delete the flow
                del self.flow_to_buffer[flow]

    # paketize packet and send
    def packetize_send(self, flow, is_fin, data, port):
        source = flow[0]
        destination = flow[1]
        total_packets = len(data) / utils.MAX_PACKET_SIZE
        for x in range(total_packets):
            packet = data[x * utils.MAX_PACKET_SIZE : (x + 1) * utils.MAX_PACKET_SIZE]
            self.send(Packet(source, destination, True, False, packet), port)
        leftovers = total_packets * utils.MAX_PACKET_SIZE
        last_packet = Packet(source, destination, True, is_fin, data[leftovers:])
        self.send(last_packet, port)
