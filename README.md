# CapFlow

CapFlow is an OpenFlow application for the Ryu controller built for the SDNHub Hackaton. 

The main goal of this application is redirect all devices connected to a wifi network to a
web site for authentication. 

## Installation
You need to install [Ryu OpenFlow controller](http://osrg.github.io/ryu/).
Then you need to setup your topology with a single switch and edit config.py.
Finally, you can start the contorller by running `ryu-manager CapFlow.py`
