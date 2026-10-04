# --- Networks ---
acl localnet src 10.0.0.0/8 192.168.0.0/16
acl SSL_ports port 443
acl Safe_ports port 80 443 21 1025-65535
acl CONNECT method CONNECT
acl metadata dst 169.254.169.254
acl maxconn_limit maxconn 50

# --- Access rules (order matters) ---
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access deny to_localhost
http_access deny metadata
http_access deny maxconn_limit localnet
http_access allow localhost manager
http_access deny manager
http_access allow localnet
http_access deny all

# --- Listen on internal interface only ---
http_port 10.0.0.1:3128

# --- Disable unused services ---
icp_port 0
htcp_port 0
snmp_port 0

# --- Hide identity ---
httpd_suppress_version_string on
via off
forwarded_for delete
visible_hostname proxy
strip_query_terms on

# --- Limits ---
request_header_max_size 64 KB
reply_body_max_size 500 MB
client_lifetime 1 hour

cache_effective_user squid
