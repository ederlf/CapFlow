
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

# Us
import config
import util

class Proto(object):
    ETHER_IP = 0x800
    ETHER_ARP = 0x806
    IP_UDP = 17
    IP_TCP = 6
    TCP_HTTP = 80
    UDP_DNS = 53


class CapFlow(app_manager.RyuApp):


    def __init__(self, *args, **kwargs):
        super(CapFlow, self).__init__(*args, **kwargs)
        self.mac_to_port = collections.defaultdict(dict)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print "Clear rule table"
        util.delete_flow(datapath, parser.OFPMatch())

        # Send everything to ctrl
        print "Install sending to controller rule"
        util.add_flow(datapath,
            parser.OFPMatch(),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
            priority=2,
        )

        # So we don't need to learn auth server location
        # TODO: this assumes we are controlling only a single switch!
        self.mac_to_port[datapath.id][config.AUTH_SERVER_MAC] = config.AUTH_SERVER_PORT


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
            util.add_flow(datapath,
                parser.OFPMatch(
                    eth_dst=nw_src,
                ),
                [parser.OFPActionOutput(in_port),],
                priority=10,
                msg=msg,
            )

    
        if eth.ethertype == Proto.ETHER_ARP:
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
            util.add_flow(datapath,
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

        if eth.ethertype == Proto.ETHER_IP:
            print "is IP flow"
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            if ip.proto == 1:
                print "ICMP? skipping"
                pass
            if ip.proto == Proto.IP_UDP:
                print "UDP"
                _udp = pkt.get_protocols(udp.udp)[0]
                if _udp.dst_port == Proto.UDP_DNS:
                   print "DNS bypass"
                   util.add_flow(datapath,
                        parser.OFPMatch(
                            in_port=in_port,
                            eth_src=nw_src,
                            eth_dst=nw_dst,
                            eth_type=Proto.ETHER_IP,
                            ip_proto=Proto.IP_UDP,
                            udp_dst=Proto.UDP_DNS,
                        ),
                        [parser.OFPActionOutput(config.AUTH_SERVER_PORT)],
                        priority=100,
                        msg=msg,
                    )
            elif ip.proto == Proto.IP_TCP:
                print "TCP"
                _tcp = pkt.get_protocols(tcp.tcp)[0]
                print _tcp
                if _tcp.dst_port == Proto.TCP_HTTP:
                    print "Is HTTP traffic, installing NAT entry"
                    util.add_flow(datapath,
                        parser.OFPMatch(
                            in_port=config.AUTH_SERVER_PORT,
                            eth_src=nw_dst,
                            eth_dst=nw_src,
                            eth_type=Proto.ETHER_IP,
                            ip_proto=Proto.IP_TCP,
                            tcp_dst=_tcp.src_port,
                            tcp_src=_tcp.dst_port,
                            ipv4_src=config.AUTH_SERVER_IP,
                            ipv4_dst=ip.src,
                        ),
                        [parser.OFPActionSetField(ipv4_src=ip.dst),
                         parser.OFPActionOutput(in_port)
                        ],
                        priority=1000,
                    )

                    util.add_flow(datapath,
                        parser.OFPMatch(
                            in_port=in_port,
                            eth_src=nw_src,
                            eth_dst=nw_dst,
                            eth_type=Proto.ETHER_IP,
                            ip_proto=Proto.IP_TCP,
                            tcp_dst=_tcp.dst_port,
                            tcp_src=_tcp.src_port,
                            ipv4_src=ip.src,
                            ipv4_dst=ip.dst,
                        ),
                        [parser.OFPActionSetField(ipv4_dst=config.AUTH_SERVER_IP),
                         parser.OFPActionOutput(config.AUTH_SERVER_PORT)
                        ],
                        priority=1000,
                        msg=msg,
                    )
                                        
            else:
                print "Unknown IP proto, dropping"
                util.add_flow(datapath,
                    parser.OFPMatch(
                        in_port=in_port,
                        eth_src=nw_src,
                        eth_dst=nw_dst,
                        eth_type=Proto.ETHER_IP,
                        ip_proto=ip.proto,
                    ),
                    [],
                    priority=10,
                    msg=msg,
                )
