TLS certificates and keys of cocosmail

Each listener in COCOSMAIL_SMTPD_DSNS and COCOSMAIL_POP3D_DSNS ends with a
certificate name, CERT in IP:PORT:HOSTNAME:ssl|nossl:CERT. cocosmail loads:

  smtp-CERT.crt and smtp-CERT.key   for SMTP (SSL and STARTTLS)
  pop3-CERT.crt and pop3-CERT.key   for POP3

The .crt file is the full chain (certificate and intermediates), the .key file
the private key, both in PEM format. With Let's Encrypt (certbot):

  cp /etc/letsencrypt/live/mail.example.com/fullchain.pem smtp-example.com.crt
  cp /etc/letsencrypt/live/mail.example.com/privkey.pem   smtp-example.com.key

A self-signed certificate for testing:

  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj /CN=mail.example.com \
    -keyout smtp-example.com.key -out smtp-example.com.crt

Keep the .key files readable by the cocosmail user only (chmod 600).
