# lynt-antispam
Simple WP antispam

It uses 6 methods:

a) honeypot field "nick", it is hidden by CSS - only bots will fill it

b) block comments with BB code [url=...]

c) HTTPBL (DNSBL) from http://www.projecthoneypot.org - you need API key

d) Block comment with common bad words

e) Block direct POST requests (no referer)

f) Swap regular comment textarea with honeypot field
