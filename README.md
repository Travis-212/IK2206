# IK2206
Internet Security and Privacy

##VPN manual:

This VPN is a port forwarding type and for testing/running it you need the commands below:
in order to start the session you MUST have a server listening to a port like 2206

java ForwardServer --handshakeport=2206 --usercert=server.pem --cacert=ca.pem --key=server-private.der

then in order to start client/s you use:

java ForwardClient --handshakehost=localhost --handshakeport=2206 --targethost=localhost --targetport=9876 --usercert=client.pem --cacert=ca.pem --key=client-private.der



PGP lab commands needed:
==========================================

for generating a key (use default values)

gpg --gen-key

==========================================

for exporting your public key

gpg --output mygpg.key --armor --export your_email@address.com

NB: --armor creates ascii armored output so that it would be readable for you and not in binary or any other format

==========================================

for signing someone's key

gpg --ask-cert-level --sign-key someone@example.com

==========================================

Signing and Encrypting with two recipients

gpg --armor -r gpg@netsec.lab.ssvl.kth.se -r youremail@kth.se -se gpg-both-gsig.txt

==========================================

Decryption

gpg --decrypt gpg-both.asc

Remember to choose only those messages signed correctly with RSA between you and the course admin
For example a proper one would look like this;

gpg: encrypted with 2048-bit RSA key, ID 48ADFE9470379765, created 2019-11-23

      "omid hazara <hazara@kth.se>"
      
5de840413e0ada17552258acebdd24a924a2d5c4

gpg: Signature made Sun Nov 24 16:41:43 2019 CET

gpg:                using RSA key B49B862B57B8F09A

gpg: Good signature from "Internet Security and Privacy (IK2206) <gpg@netsec.lab.ssvl.kth.se>" [full]


==========================================
