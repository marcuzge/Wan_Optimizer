import wan_optimizer
from tcp_packet import Packet
import utils

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into variable-sized
    blocks based on the contents of the file.

    This WAN optimizer should implement part 2 of project 4.
    """

    # The string of bits to compare the lower order 13 bits of hash to
    GLOBAL_MATCH_BITSTRING = '0111011001010'
    WINDOW_SIZE = 48

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
        functionality described in part 2.  You are welcome to implement private
        helper fuctions that you call here. You should *not* be calling any functions
        or directly accessing any variables in the other middlebox on the other side of 
        the WAN; this WAN optimizer should operate based only on its own local state
        and packets that have been received.
        """

        flow = (packet.src, packet.dest)
        if not flow in self.flow_to_buffer:
            self.flow_to_buffer[flow] = ""
        WINDOW_SIZE = 48

        if packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middlebox;
            # send the packet there.
            if packet.is_raw_data:
                self.send(packet, self.address_to_port[packet.dest])
                self.flow_to_buffer[flow] += packet.payload
                pointer = WINDOW_SIZE
                buffer_size = len(self.flow_to_buffer[flow])
                while pointer <= buffer_size:
                    data_hash = utils.get_hash(self.flow_to_buffer[flow][pointer - WINDOW_SIZE : pointer])
                    if (utils.get_last_n_bits(data_hash, len(self.GLOBAL_MATCH_BITSTRING)) == self.GLOBAL_MATCH_BITSTRING):
                        current_buff = self.flow_to_buffer[flow][:pointer]
                        self.cache[utils.get_hash(current_buff)] = current_buff
                        # self.packetize_send(cache[hashed], flow, packet.is_fin, self.address_to_port[packet.dest])
                        self.flow_to_buffer[flow] = self.flow_to_buffer[flow][pointer:]
                        pointer = WINDOW_SIZE
                    else:
                        pointer += 1
            else:
                self.packetize_send(flow, packet.is_fin, self.cache[packet.payload], self.address_to_port[packet.dest])
            
            if packet.is_fin:
                data = utils.get_hash(self.flow_to_buffer[flow])
                if data is not None:
                    current_buff = self.flow_to_buffer[flow]
                    self.cache[data] = current_buff
                del self.flow_to_buffer[flow]
            
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.
            self.flow_to_buffer[flow] += packet.payload
            pointer = WINDOW_SIZE
            buffer_size = len(self.flow_to_buffer[flow])
            while pointer <= buffer_size:
                data_hash = utils.get_hash(self.flow_to_buffer[flow][pointer- WINDOW_SIZE:pointer])
                if (utils.get_last_n_bits(data_hash, len(self.GLOBAL_MATCH_BITSTRING)) == self.GLOBAL_MATCH_BITSTRING):                    
                    block = utils.get_hash(self.flow_to_buffer[flow][:pointer])
                    if block not in self.cache: 
                        current_buff = self.flow_to_buffer[flow][:pointer]
                        self.cache[block] = current_buff
                        self.packetize_send(flow, False, current_buff, self.wan_port)                  
                    else: 
                        src, dest = flow
                        self.send(Packet(src,dest, False, False, block), self.wan_port)
                    self.flow_to_buffer[flow] = self.flow_to_buffer[flow][pointer:]
                    pointer = WINDOW_SIZE
                else:
                    pointer += 1

            if packet.is_fin:
                flow = (packet.src, packet.dest)
                current_buff = self.flow_to_buffer[flow]
                data_hash = utils.get_hash(current_buff)
                if data_hash not in self.cache:
                    current_buff = self.flow_to_buffer[flow]
                    if data_hash is not None:
                        self.cache[data_hash] = current_buff
                    self.packetize_send(flow, True, current_buff, self.wan_port)
                else:
                    src, dest = flow[0], flow[1]
                    hash_packet = Packet(src, dest, False, True, data_hash) # set is_fin
                    self.send(hash_packet, self.wan_port)
                del self.flow_to_buffer[flow]

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
