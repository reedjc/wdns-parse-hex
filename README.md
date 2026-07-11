
This is a simple DNS wire parser that uses the WDNS library.
See https://github.com/farsightsec/wdns

Compile like:

cc -I /usr/local/include/  -o wdns-parse-hex -L/usr/local/lib/ -lwdns wdns-parse-hex.c  -Wl,-R/usr/local/lib

Run like:

./wdns-parse-hex "FE A0 81 80 00 01 00 01 00 00 00 00 06 67 69 74 68 75 62 03 63 6F 6D 00 00 01 00 01 C0 0C 00 01 00 01 00 00 00 3C 00 04 8C 52 79 03"
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 65184
;; flags: qr rd ra 
;; QUESTION SECTION:
;github.com. IN A

;; ANSWER SECTION:
github.com. 60 IN A 140.82.121.3

--------------

I have written around seven DNS wire parsers.
This time while auditing wdns with Claude and AI,
I had claude write this code as an AI and wdns experiment.

