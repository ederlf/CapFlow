# CapFlow in Mininet

These are the instructions to run CapFlow inside Mininet environment

## Prerequisites
`sudo apt-get install wget gunicorn`

## Testing

1. run `sudo ./mininet_wrapper.py`. This creates the topology with a single switch and 4 hosts
    (h1=controller, h2=internet gateway, h3=captive portal server, h4=client)
2. run the controller
  * `xterm h1`
  * `./start-ctrl.sh`
3. run the "internet"
  * `xterm h2`
  * `./start-internet.sh`
4. run the captive portal
  * `xterm h3`
  * `./start-captive.sh`
5. run the client
  * `xterm h4`
  * either `./start-client.sh` or `firefox` (and go to your well-known webpage 10.0.0.2)
