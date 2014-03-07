def add_flow(datapath, match, actions, priority=None, command=None, msg=None):
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
        out = parser.OFPPacketOut(
                datapath=datapath,
                actions=[parser.OFPActionOutput(ofproto.OFPP_TABLE)],
                in_port=1,
                buffer_id=0xffffffff,
                data=msg.data)
        datapath.send_msg(out)


def delete_flow(datapath, match, command=None):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    if not command:
        command = ofproto.OFPFC_DELETE

    mod = parser.OFPFlowMod(datapath=datapath, match=match, command=command,
        out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
    )
    datapath.send_msg(mod)
