# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Python
import collections

# Ryu
from ryu.base import app_manager
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.lib.packet import ethernet, ipv4, tcp, udp
from ryu.lib.packet import packet
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3

class CapFlow(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    ETHER_IP = 0x800
    ETHER_ARP = 0x806
    IP_UDP = 17
    IP_TCP = 6
    TCP_HTTP = 80
    UDP_DNS = 53

    GATEWAY_MAC = "42:a2:76:7d:2e:72"
    SERVER_IP = "192.168.17.1"
    
    PORT_INTERNET = 2

    def __init__(self, *args, **kwargs):
        super(CapFlow, self).__init__(*args, **kwargs)
        self.mac_to_port = collections.defaultdict(dict)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print "Clear rule table"
        self.delete_flow(datapath, parser.OFPMatch())

        # Send everything to ctrl
        print "Install sending to controller rule"
        self.add_flow(datapath,
            parser.OFPMatch(),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
            priority=2,
        )

#        # install table-miss flow entry: Drop
#        #
#        print "Installing drop entry"
#        self.add_flow(datapath, 0, parser.OFPMatch(), [])
#
#        #Rule to direct DNS traffic to the internet
#        print "Installing DNS bypass"
#        self.add_flow(
#            datapath, 100,
#            parser.OFPMatch(
#                eth_type=self.ETHER_IP,
#                ip_proto=self.IP_UDP,
#                udp_src=self.UDP_DNS,
#            ),
#            [parser.OFPActionOutput(self.PORT_INTERNET),]
#        )
#
#        #Flow to redirect HTTP traffic
#        self.add_flow(datapath, 100,
#            parser.OFPMatch(
#                eth_type=self.ETHER_IP,
#                ip_proto=self.IP_TCP,
#                tcp_src=self.TCP_HTTP,
#            )
#            [parser.OFPActionOutput(self.PORT_INTERNET),],
#        )
        self.mac_to_port[datapath.id][self.GATEWAY_MAC] = self.PORT_INTERNET

    @staticmethod
    def add_flow(self, datapath, match, actions, priority = None, command=None, msg=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if not command:
            command = ofproto.OFPFC_ADD
        if not priority:
            priority = ofproto.OFP_DEFAULT_PRIORITY


        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst, command=command)

        datapath.send_msg(mod)
        if msg:
            out = parser.OFPPacketOut(datapath=datapath, actions=[parser.OFPActionOutput(ofproto.OFPP_TABLE)], in_port=1,
                buffer_id=0xffffffff, data=msg.data)
            datapath.send_msg(out)
    
    @staticmethod
    def delete_flow(self, datapath, match, command=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if not command:
            command = ofproto.OFPFC_DELETE

        mod = parser.OFPFlowMod(datapath=datapath, match=match, command=command,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        nw_dst = eth.dst
        nw_src = eth.src

        dpid = datapath.id

        self.logger.info("packet in %s %s %s %s", dpid, nw_src, nw_dst, in_port)

        if nw_src not in self.mac_to_port[dpid]:
            print "New client: dpid", dpid, "mac", nw_src, "port", in_port
            self.mac_to_port[dpid][nw_src] = in_port
            print "Installing *->%s forwarding rule" % nw_src
            self.add_flow(datapath,
                parser.OFPMatch(
                    eth_dst=nw_src,
                ),
                [parser.OFPActionOutput(in_port),],
                priority=10,
                msg=msg,
            )

    
        if eth.ethertype == self.ETHER_ARP:
            print "ARP"
            port = self.mac_to_port[dpid].get(nw_dst, ofproto.OFPP_FLOOD)
            out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=[parser.OFPActionOutput(port)],
                    data=msg.data,
                )
            datapath.send_msg(out)
            return

        if nw_dst not in self.mac_to_port[dpid]:
            print "Unknown destination!",
            return
        out_port = self.mac_to_port[dpid][nw_dst]
        
        is_authenticated = False

        if is_authenticated:
            print "authenticated"
            print "Installing", nw_src, "to", nw_dst, "bypass"
            self.add_flow(datapath,
                parser.OFPMatch(
                    eth_src=nw_src,
                    eth_dst=nw_dst,
                ),
                [parser.OFPActionOutput(out_port),],
                priority=100,
                msg=msg,
            )
            return

        # not authenticated
        out_port = self.mac_to_port[dpid][nw_dst]

        if eth.ethertype == self.ETHER_IP:
            print "is IP flow"
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            if ip.proto == 1:
                print "ICMP? skipping"
                pass
            if ip.proto == self.IP_UDP:
                print "UDP"
                _udp = pkt.get_protocols(udp.udp)[0]
                if _udp.dst_port == 53:
                   print "DNS bypass"
                   self.add_flow(datapath,
                        parser.OFPMatch(
                            in_port=in_port,
                            eth_src=nw_src,
                            eth_dst=nw_dst,
                            eth_type=self.ETHER_IP,
                            ip_proto=self.IP_UDP,
                            udp_dst=53,
                        ),
                        [parser.OFPActionOutput(self.PORT_INTERNET)],
                        priority=100,
                        msg=msg,
                    )
            elif ip.proto == self.IP_TCP:
                print "TCP"
                _tcp = pkt.get_protocols(tcp.tcp)[0]
                print _tcp
                if _tcp.dst_port == self.TCP_HTTP:
                    print "Is HTTP traffic, installing NAT entry"
                    self.add_flow(datapath,
                        parser.OFPMatch(
                            in_port=self.PORT_INTERNET,
                            eth_src=nw_dst,
                            eth_dst=nw_src,
                            eth_type=self.ETHER_IP,
                            ip_proto=self.IP_TCP,
                            tcp_dst=_tcp.src_port,
                            tcp_src=_tcp.dst_port,
                            ipv4_src=self.SERVER_IP,
                            ipv4_dst=ip.src,
                        ),
                        [parser.OFPActionSetField(ipv4_src=ip.dst),
                         parser.OFPActionOutput(in_port)
                        ],
                        priority=1000,
                    )

                    self.add_flow(datapath,
                        parser.OFPMatch(
                            in_port=in_port,
                            eth_src=nw_src,
                            eth_dst=nw_dst,
                            eth_type=self.ETHER_IP,
                            ip_proto=self.IP_TCP,
                            tcp_dst=_tcp.dst_port,
                            tcp_src=_tcp.src_port,
                            ipv4_src=ip.src,
                            ipv4_dst=ip.dst,
                        ),
                        [parser.OFPActionSetField(ipv4_dst=self.SERVER_IP),
                         parser.OFPActionOutput(self.PORT_INTERNET)
                        ],
                        priority=1000,
                        msg=msg,
                    )
                                        
            else:
                print "Unknown IP proto, dropping"
                self.add_flow(datapath,
                    parser.OFPMatch(
                        in_port=in_port,
                        eth_src=nw_src,
                        eth_dst=nw_dst,
                        eth_type=self.ETHER_IP,
                        ip_proto=ip.proto,
                    ),
                    [],
                    priority=10,
                    msg=msg,
                )
