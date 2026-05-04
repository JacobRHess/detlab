# detlab Zeek site config. Loads the protocol scripts we care about
# for network detections and ensures dns.log captures TXT/MX answers.

@load protocols/conn
@load protocols/dns
@load protocols/http
@load protocols/ssl
@load protocols/ssh
@load protocols/smtp

# Make DNS log richer for tunneling detection: keep all answers + TTLs.
redef DNS::Info$total_answers += 1 &optional;

# JSON output is set on the command line via -e in docker-compose.
