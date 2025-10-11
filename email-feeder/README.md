# Email Feeder

This document maps the different components and behaviors of the Email Feeder
system.

## Purpose

The purpose of the Email Feeder system is to provide a report of the different
malicious artefacts that have been analyzed.

The report is sent via email to the user who triggered the lookup via SMTP.

## Use cases

### The user sends an email request for analysis

In order to know whether an email may be malicious, the user will have to
forward the email to the `user@organisation.com` (configured in [`./config-sample.json['mail-connectors']`](./config-sample.json)).

In order for the service to receive the email, an IMAP server is expected to be
hosted. The service will connect to the IMAP server with the configured account
and periodically fetch all the `UNSEEN` emails, which are all expected to be
user requests for analysis.

The service then process each received email, looking into the headers,
attachments, body itself, and so on, in order to detect any kind of malicious
intent.

### The service sends a report to the user

Once the service finished processing an email, it sends a response back to the
user who forwarded it to let them know whether it was malicious.

To do so, an SMTP server is expected to be hosted and configured in a way that
the `SUSPICIOUS` user (configured in [`./config-sample.json['mail']['username']`](./config-sample.json))
can use it to send the response email.

## Testing

If you are trying to implement a feature of fix a bug, you will likely want to
test whether you broke something.

There is a minimal IMAP and Minio setup by the `docker-compose.dev.yaml` file.

It contains both services and expose ports allowing you to test the `email-feeder`
service without deploying a whole architecture.

To start the IMAP server and the Minio storage services, you can type the
following command :
```bash
docker compose -f docker-compose.dev.yaml up -d
```

Once all services are up, you can access them through those ports :
```
3025 -- SMTP
3110 -- POP3
3143 -- IMAP
3465 -- SMTPS
3995 -- POP3S
3993 -- IMAPS
9000 -- Minio S3 server
9001 -- Minio admin web panel
```

The default IMAP user credentials are :
```
username: imap_user@localhost
password: imap_password
```

The default Minio user credentials are :
```
username: minioadmin
password: minioadmin
```

If you are not happy with them, you can edit them in the `docker-compose.dev.yaml`
file.

For the default setup, here is a possible matching `config.json` file :
```json
{
  "mail-connectors": {
    "imap": {
      "imap-dev": {
        "enable": true,
        "host": "localhost",
        "port": 3143,
        "login": "imap_user",
        "password": "imap_password",
        "mailbox_to_monitor": "INBOX"
      }
    },
    "imaps": {
      "imaps-dev": {
        "enable": false,
        "host": "localhost",
        "port": 3993,
        "login": "imap_user",
        "password": "imap_password",
        "certfile": false,
        "keyfile": false,
        "mailbox_to_monitor": "INBOX"
      },
      "imaps-prod": {
        "enable": false,
        "host": "localhost",
        "port": 3993,
        "login": "imap_user",
        "password": "imap_password",
        "certfile": false,
        "keyfile": false,
        "mailbox_to_monitor": "INBOX"
      }
    }
  },
  "working-path": "/tmp/suspicious",
  "timer-inbox-emails": 10,
  "minio": {
    "endpoint": "localhost:9000",
    "access_key": "minioadmin",
    "secret_key": "minioadmin",
    "secure": false
  },
  "mail": {
    "server": "localhost",
    "port": 3025,
    "username": "SUSPICIOUS",
    "footer": "Limited Distribution",
    "group": "Your Cybersecurity Team Name",
    "suspicious_web": "https://suspicious.test/submissions/",
    "global": "test.com",
    "global_url": "https://www.test.com/en",
    "socials": {
      "facebook": "https://fr-fr.facebook.com/test",
      "twitter": "https://x.com/test",
      "instagram": "https://www.instagram.com/test",
      "linkedin": "https://www.linkedin.com/company/test",
      "youtube": "https://www.youtube.com/test"
    },
    "glossary": "https://glossary_to_cyber terms",
    "inquiry": "mailto:inquryemail@yourcompany.com",
    "inquiry_text": "inquryemail@yourcompany.com",
    "submissions": "https://suspicious.test/submissions/",
    "security": "mailto:yoursecuritymail@yourcompany.com",
    "security_msg": "yoursecuritymail@yourcompany.com",
    "logos": {
      "company": "data:image/png;base64,Base64 text of your company logo",
      "acknowledge-badmail": "data:image/png;base64,The Base 64 image for the bad acknowledge mail"
    }
  }
}
```

Once you're down testing or just want ot save resources, you can shutdown the
services using this command :
```bash
docker compose -f docker-compose.dev.yaml down
```