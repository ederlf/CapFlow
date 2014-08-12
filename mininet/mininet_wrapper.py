#!/usr/bin/python
# vim: et
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class InbandController( RemoteController ):

    def checkListening( self ):
        "Overridden to do nothing."
        return

def runner():
    net = Mininet(topo=None,
                  build=False,
                  autoSetMacs=True)

    net.addController( 'c0',
                       controller=InbandController,
                       ip='10.0.0.1'  )

    # h1 = controller
    h1 = net.addHost( 'h1', ip='10.0.0.1' )
    # h2 = internet server/gateway
    h2 = net.addHost( 'h2', ip='10.0.0.2' )
    # h3 = captive server
    h3 = net.addHost( 'h3', ip='10.0.0.3' )
    # h4 = client
    h4 = net.addHost( 'h4', ip='10.0.0.4' )

    s1 = net.addSwitch( 's1', cls=OVSSwitch )

    net.addLink( h1, s1 )
    net.addLink( h2, s1 )
    net.addLink( h3, s1 )
    net.addLink( h4, s1 )

    net.start()
    s1.cmd('ifconfig s1 10.0.0.10')
    s1.cmd('ovs-vsctl set bridge s1 protocols=OpenFlow13')
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'debug' )
    runner()
