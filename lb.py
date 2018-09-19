import json
import logging
import random
import sys

from ryu import cfg

from ryu.base import app_manager
from ryu.controller import ofp_event

from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3

logger    = logging.getLogger(__file__)
formatter = logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s')
logger.propagate = False
logger.setLevel(logging.INFO)

if not logger.handlers:
    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(formatter)
    logger.addHandler(stdout_handler)


_SERVICE_TYPE = (
    "red",
    "blue"
)

_ARP_QUERY    = 1
_ARP_RESPONSE = 2

_PROACTIVE_MODE = True

def _load_config_file():
    try:
        with open(cfg.CONF['test-switch']['dir']) as file_handler:
            return json.load(file_handler)
    except:
        return json.load(sys.stdin)


class LoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancer, self).__init__(*args, **kwargs)
        # define your own attributes and states maintained by the controller
        # WRITE YOUR CODE HERE
        usr_config = _load_config_file()

        self._switch_mac_address = usr_config["service_mac"]
        self._switch_blue_ip     = usr_config["service_ips"]["blue"]
        self._switch_red_ip      = usr_config["service_ips"]["red"]

        self._blue_servers_ip = usr_config["server_ips"]["blue"]
        self._red_servers_ip  = usr_config["server_ips"]["red"]

        self._client_ip_mac_mapping = dict()
        self._mac_port_mapping      = dict()
        self._server_ip_mac_mapping = dict()
        for ip_address in self._blue_servers_ip + self._red_servers_ip:
            self._server_ip_mac_mapping[ip_address] = None

        logger.critical("Switch is now working in **{mode}** mode".format(
            mode="PROACTIVE" if _PROACTIVE_MODE else "REACTIVE"
        ))

    def __arp_packet_factory(self, packet_type="query", switch_ip="", dst_mac="", dst_ip="") -> packet.Packet:
        '''
        A factory for ARP packet.
        It customize ARP query/response for different service types
        '''
        assert packet_type in ("query", "response"), "Not a valid packet type (query/response)"
        assert dst_ip,    "Both query and response require valid destination IP address"
        assert switch_ip, "Must specify the switch IP"

        if packet_type == "response":
            assert dst_mac, "a response packet should have a valid destination MAC address"

        if packet_type == "query":
            arp_body = arp.arp_ip(
                _ARP_QUERY, 
                self._switch_mac_address, switch_ip,
                '00:00:00:00:00:00',      dst_ip
            )
            ethernet_head = ethernet.ethernet(
                src=self._switch_mac_address,
                dst="ff:ff:ff:ff:ff:ff",
                ethertype=ether.ETH_TYPE_ARP
            )

        else:
            arp_body = arp.arp_ip(
                _ARP_RESPONSE,
                self._switch_mac_address, switch_ip,
                dst_mac,                  dst_ip
            )
            ethernet_head = ethernet.ethernet(
                src=self._switch_mac_address,
                dst=dst_mac,
                ethertype=ether.ETH_TYPE_ARP
            )

        raw_packet = packet.Packet()
        raw_packet.add_protocol(ethernet_head)
        raw_packet.add_protocol(arp_body)
        raw_packet.serialize()

        return raw_packet

    def __extract_ip_and_mac_src_dst(self, pkt) -> {str : str}:
        '''
        Extract the IP and MAC source and destination addresses from the packet
        '''
        readable_packet = packet.Packet(pkt) if not isinstance(pkt, packet.Packet) else pkt
        ether_info      = readable_packet.get_protocol(ethernet.ethernet)

        if ipv4.ipv4 in readable_packet:
            ipv4_info = readable_packet.get_protocol(ipv4.ipv4)
            return {
                "ip_src"  : ipv4_info.src,
                "ip_dst"  : ipv4_info.dst,
                "mac_src" : ether_info.src,
                "mac_dst" : ether_info.dst
            }
        else:
            arp_info = readable_packet.get_protocol(arp.arp)
            return {
                "ip_src"  : arp_info.src_ip,
                "ip_dst"  : arp_info.dst_ip,
                "mac_src" : arp_info.src_mac,
                "mac_dst" : arp_info.dst_mac
            }

    def __send_single_packet_action(self, *, datapath, out_port, payload) -> None:
        '''
        The function that handles all the Action instances sending
        '''
        assert datapath, "There must be a valid datapath"
        assert payload,  "There must be a payload"

        action = [
            datapath.ofproto_parser.OFPActionOutput(out_port)
        ]

        packet_out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=action,
            data=payload.data
        )
        datapath.send_msg(packet_out)

        
    def send_arp_requests_to_servers(self, dp) -> None:
        # send arp requests to servers to learn their mac addresses
        # WRITE YOUR CODE HERE

        for ip_address in self._red_servers_ip + self._blue_servers_ip:
            payload = self.__arp_packet_factory(
                packet_type="query",
                switch_ip=self._switch_red_ip,
                dst_ip=ip_address
            )

            self.__send_single_packet_action(
                datapath=dp,
                out_port=dp.ofproto.OFPP_FLOOD,
                payload=payload
            )
            logger.info("Sent FLOOD ARP to {}".format(ip_address))     

    def __respond_arp(self, ip_in_question, questioner_mac, questioner_ip) -> None:
        '''
        respond to clients' or servers' arp query
        '''
        return self.__arp_packet_factory(
            packet_type="response",
            switch_ip=ip_in_question,
            dst_mac=questioner_mac,
            dst_ip=questioner_ip
        )        

    def __get_server_by_type(self, *, service_type) -> "ip_address":
        '''
        The function that chooses the server by the service type requested
        Can be rewriten or extended to use other algorithms (instead of
        randomly choosing one)
        '''
        assert service_type in _SERVICE_TYPE, "The service type is not valid"

        # server selection algorithm implemented below 
        # RANDOMLY CHOOSE A SERVER
        if service_type == "blue":
            return random.choice(self._blue_servers_ip)
        else:
            return random.choice(self._red_servers_ip)
           
    def send_proxied_arp_response(self):
        # relay arp response to clients or servers
        # no need to insert entries into the flow table
        # WRITE YOUR CODE HERE
        raise NotImplementedError

    def send_proxied_arp_request(self):
        # relay arp requests to clients or servers
        # no need to insert entries into the flow table
        # WRITE YOUR CODE HERE
        raise NotImplementedError

    def add_entry_pair(self, datapath, input_port, client_ip, service_ip):
        '''
        The function that will only be used in proactive mode.
        This function inserts two flow entries (client -> server) and (server -> client)
        Idle timeout is about 1 sec
        '''
        service_type = "red" if service_ip == self._switch_red_ip else "blue"
        server_ip    = self.__get_server_by_type(service_type=service_type)
        server_mac   = self._server_ip_mac_mapping[server_ip]

        client_to_server_match_obj = datapath.ofproto_parser.OFPMatch(
            in_port=input_port,
            eth_type=ether.ETH_TYPE_IP,
            ipv4_src=client_ip,
            ipv4_dst=service_ip
        )
        client_to_server_action_obj = [
            datapath.ofproto_parser.OFPActionSetField(eth_src=self._switch_mac_address),
            datapath.ofproto_parser.OFPActionSetField(eth_dst=server_mac),
            datapath.ofproto_parser.OFPActionSetField(ipv4_dst=server_ip),
            datapath.ofproto_parser.OFPActionOutput(
                self._mac_port_mapping[server_mac]
            )
        ]

        client_mac = self._client_ip_mac_mapping[client_ip]
        server_to_client_match_obj = datapath.ofproto_parser.OFPMatch(
            in_port=self._mac_port_mapping[server_mac],
            eth_type=ether.ETH_TYPE_IP,
            ipv4_src=server_ip,
            ipv4_dst=client_ip
        )
        server_to_client_action_obj = [
            datapath.ofproto_parser.OFPActionSetField(eth_src=self._switch_mac_address),
            datapath.ofproto_parser.OFPActionSetField(eth_dst=client_mac),
            datapath.ofproto_parser.OFPActionSetField(
                ipv4_src=self._switch_red_ip if service_type == "red" else self._switch_blue_ip
            ),
            datapath.ofproto_parser.OFPActionSetField(ipv4_dst=client_ip),
            datapath.ofproto_parser.OFPActionOutput(
                self._mac_port_mapping[client_mac]
            )
        ]

        logger.info("Add a flow entry pair (client {} --> server {})".format(
            client_ip, server_ip
        ))
        self.add_flow_entry(datapath, 1, client_to_server_match_obj, client_to_server_action_obj, timeout=1)
        self.add_flow_entry(datapath, 1, server_to_client_match_obj, server_to_client_action_obj, timeout=1)
        
    def add_flow_entry(self, datapath, priority, match, actions, timeout=10):
        # helper function to insert flow entries into flow table
        # by default, the idle_timeout is set to be 10 seconds
        # WRITE YOUR CODE HERE
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath, 
            priority=priority,
            match=match,
            idle_timeout=timeout,
            instructions=inst
        )
        datapath.send_msg(mod)

    def __ip_eth_header_spoof(self, src_ip, src_mac, dst_ip, dst_mac, pkt) -> packet.Packet:
        '''
        Spoofing the Ethernet packet (and the IPv4)
        '''
        general_header = packet.Packet()
        ethernet_head  = ethernet.ethernet(
            src=src_mac,
            dst=dst_mac,
            ethertype=ether_types.ETH_TYPE_IP
        )
        
        if icmp.icmp in pkt:
            ipv4_payload = pkt.get_protocol(icmp.icmp)
        elif tcp.tcp in pkt:
            ipv4_payload = pkt.get_protocol(tcp.tcp)
        elif udp.udp in pkt:
            ipv4_payload = pkt.get_protocol(udp.udp)

        ethernet_payload     = pkt.get_protocol(ipv4.ipv4)
        ethernet_payload.src = src_ip
        ethernet_payload.dst = dst_ip
        
        general_header.add_protocol(ethernet_head)
        general_header.add_protocol(ethernet_payload)
        general_header.add_protocol(ipv4_payload)
        general_header.serialize()

        return general_header

    def add_default_entry(self, datapath) -> None:
        '''
        This is to make OpenFlow 1.0 compatible with 1.3
        Allows all the packets be forwarded to the controller if they do
        not match the table
        '''
        parser = datapath.ofproto_parser
        match  = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                datapath.ofproto.OFPP_CONTROLLER,
                datapath.ofproto.OFPCML_NO_BUFFER
            )
        ]
        self.add_flow_entry(datapath, 0, match, actions, timeout=0)       

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def pre_service_preparation(self, ev):
        '''
        the first handler to be triggered
        this handler adds a default entry to the switch
        this handler sends ARP requests to all servers
        '''
        datapath = ev.msg.datapath
        self.add_default_entry(datapath)
        self.send_arp_requests_to_servers(datapath)

    def __update_switch_status_tables(self, ip_src, mac_src, input_port):
        '''
        update the:
        1. MAC address to port # Map
        2. Server IP address to Server MAC Map
        3. Client IP address to Client MAC Map
        '''
        if ip_src not in (self._switch_blue_ip, self._switch_red_ip):
            self._mac_port_mapping[mac_src] = input_port
            if ip_src in self._server_ip_mac_mapping:
                self._server_ip_mac_mapping[ip_src] = mac_src
            else:
                self._client_ip_mac_mapping[ip_src] = mac_src

    def __multiplexer(self, datapath, input_port, pkt, type_hint) -> None:
        '''
        the multiplxer that handles the arp packet
        '''
        addr_info = self.__extract_ip_and_mac_src_dst(pkt)
        ip_src, ip_dst   = addr_info["ip_src"],  addr_info["ip_dst"]
        mac_src, mac_dst = addr_info["mac_src"], addr_info["mac_dst"]

        self.__update_switch_status_tables(ip_src, mac_src, input_port)
        # update the port map

        if type_hint == ether_types.ETH_TYPE_ARP:
            if pkt.get_protocol(arp.arp).opcode == _ARP_QUERY:
                logger.info("Has an ARP ({} asking for {})".format(ip_src, ip_dst))
                new_packet = self.__respond_arp(ip_dst, mac_src, ip_src)
                dst_mac    = mac_src
            else:
                return

        else:
            if ip_src in self._server_ip_mac_mapping:
                # If the packet comes from a server
                logger.info("Get a server packet from {} --> {}".format(ip_src, ip_dst))

                if ip_dst not in (self._switch_blue_ip, self._switch_red_ip):
                    # The packet is not head for the switch
                    # service_type = "red" if ip_src in self._red_servers_ip else "blue"
                    src_ip  = self._switch_red_ip if ip_src in self._red_servers_ip else self._switch_blue_ip
                    dst_ip  = ip_dst
                    dst_mac = self._client_ip_mac_mapping[dst_ip]
                else:
                    return

            else:
                # If the packet comes from a client
                logger.info("Get a client packet from {} --> {}".format(ip_src, ip_dst))
                # The packet is head for the servers
                if _PROACTIVE_MODE:
                    self.add_entry_pair(datapath, input_port, ip_src, ip_dst)

                src_ip  = ip_src
                dst_ip  = self.__get_server_by_type(service_type="red" if ip_dst == self._switch_red_ip else "blue")
                dst_mac = self._server_ip_mac_mapping[dst_ip]

            src_mac = self._switch_mac_address
            logger.info("Forward packet {} --> {}".format(src_ip, dst_ip))

            new_packet = self.__ip_eth_header_spoof(src_ip, src_mac, dst_ip, dst_mac, pkt)
        
        self.__send_single_packet_action(
            datapath=datapath,
            out_port=self._mac_port_mapping[dst_mac],
            payload=new_packet
        )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
        Main packet handler
        '''
        msg = ev.msg
        dp  = msg.datapath
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        in_port = msg.match["in_port"]

        if eth.ethertype in (ether_types.ETH_TYPE_ARP, ether_types.ETH_TYPE_IP):
            self.__multiplexer(dp, in_port, pkt, eth.ethertype)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        # handle FlowRemoved event	
        # WRITE YOUR CODE HERE
        logger.info("An entry pair had been removed...")
