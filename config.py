# Mac address of authentication server
AUTH_SERVER_MAC = "00:00:00:00:00:03"
# IP address of authentication server
AUTH_SERVER_IP = "10.0.0.3"
# Switch port authentication server is facing
AUTH_SERVER_PORT = 3

CTL_REST_IP = "10.0.0.1"
CTL_REST_PORT = "8080"
CTL_MAC = "00:00:00:00:00:01"

GATEWAY_MAC = "00:00:00:00:00:02"

# L2 src-dst pairs which are whitelisted and does not need to go through auth
WHITELIST = [
    (AUTH_SERVER_MAC, CTL_MAC),
    (CTL_MAC, AUTH_SERVER_MAC),
]
