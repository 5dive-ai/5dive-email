# Email for your AI employees — IT guide

## A. Use a mailbox you already run

1. Create a normal mailbox for the agent (e.g. `mike@yourfirm.com`).
2. Allow IMAP and SMTP sign-in for that one mailbox.
   - **Google Workspace:** turn on 2-step verification for the mailbox and make
     an app password (Google Account > Security > App passwords).
   - **Microsoft 365:** not yet. Microsoft turned off password sign-in for
     IMAP in 2022, so it needs the Microsoft sign-in, which is not built yet.
     Until then use B below with your Microsoft 365 as the relay for sending.
   - **Any other server:** IMAP on 993 (TLS) and SMTP submission on 587 or 465.
3. The owner runs `sudo 5dive email connect <agent> --address=<a>
   --provider=google|other [--imap-host=… --smtp-host=…] --task=<DIVE-N>`
   and pastes the password into the one-time link.

On an offline (local-only) server, a mail server on your office network works
as it is. A cloud mailbox needs: `sudo 5dive config local-only allow email`.

## B. Run the mail on this server

1. Pick a domain or subdomain for the agents, e.g. `ai.yourfirm.com`.
2. `sudo 5dive email server setup --domain=ai.yourfirm.com`
   By default the server sends mail itself, signed with its own DKIM key. That
   works from an established server. A NEW cloud account often has port 25
   out blocked at first (Hetzner until the first paid invoice, DigitalOcean
   and Vultr until you open a support ticket). Then ask the provider to open
   it, or send through a relay:
   - **Resend:** add `--relay=resend --task=<DIVE-N>`. Verify the domain in
     Resend first (resend.com, Domains, and set the records it shows), then
     paste a Resend API key into the one-time link.
   - **Your firm's mail server, Postmark or Amazon SES:**
     add `--relay-host=<their SMTP host> --relay-login=<user> --task=<DIVE-N>`.
3. Set the DNS records it prints (`sudo 5dive email server status` shows
   them again):

   | Record | Name | Value |
   |---|---|---|
   | A | mail.ai.yourfirm.com | this server's IP |
   | MX | ai.yourfirm.com | 10 mail.ai.yourfirm.com |
   | TXT (SPF) | ai.yourfirm.com | `v=spf1 a:mail.ai.yourfirm.com -all` (or your relay's include) |
   | TXT (DKIM) | oa1._domainkey.ai.yourfirm.com | printed by setup |
   | TXT (DMARC) | _dmarc.ai.yourfirm.com | `v=DMARC1; p=quarantine` |
   | PTR | this server's IP | mail.ai.yourfirm.com (ask your network provider) |

4. Open port 25 inbound to this server: from the internet, or only from the
   office network for mail inside the office.
5. `sudo 5dive email connect <agent> --self-hosted` for each agent.

The server takes mail only for the agents you connect (it is no open relay),
and each agent can send only as itself.

## Who can reach the agent

- Mail from colleagues on the agent's own domain, from anyone on the owner's
  list (`sudo 5dive email allow <agent> <address|@domain>`), and from people
  the agent has mailed reaches it at once.
- A first mail from anyone else is held on the server, and the owner gets a
  card: Allow hands it to the agent; No deletes it, and that sender's later
  mail is dropped too. Off per agent: `sudo 5dive email gate <agent> inbound off`.

## What the agent may do

- It answers anyone whose mail reached it, and colleagues on its own domain.
- A first mail to anyone else waits for the owner's Allow. A No is remembered.
- 50 mails a day per agent by default.
- Mail never authorises risky work: root commands, payments, deleting,
  settings or access wait for the owner's yes on their own channel.
- One log line per mail (time, direction, address, size) in the agent's
  `~/.claude/channels/email/messages.log`; the server's in
  `/var/lib/5dive/mail/mail.log`. Never the text.
