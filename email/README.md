# email — each agent gets its own email address

People email the agent like a colleague. The mail shows up as a chat; the agent
answers in the same thread, from its own address. 5dive hosts no mail.

Two ways to give an agent an address:

1. **A mailbox your firm already runs** (Google Workspace or any IMAP + SMTP
   server; Microsoft 365 needs a Microsoft sign-in that is not built yet). IT makes `mike@yourfirm.com`, then:
   `sudo 5dive email connect mike --address=mike@yourfirm.com --provider=google --task=<DIVE-N>`
   (the password comes through a one-time link, never on the command line).
2. **Your server's own mail server** (OpenAgent Mail) for a domain or subdomain
   your firm points at it, e.g. `mike@ai.yourfirm.com`:
   `sudo 5dive email server setup --domain=ai.yourfirm.com` (prints the DNS
   records for IT), then `sudo 5dive email connect mike --self-hosted`.
   Works with the internet off for mail inside the office.

Voicemail: a mail with an audio file (an office phone system's voicemail, a
recorded memo) reaches the agent with its transcript, heard on this server by
the local speech-to-text; the audio never leaves it.

Safety, on by default:

- A first mail FROM someone unknown is held on the server. The agent does not
  see it until the owner taps Allow; No deletes it, and that sender's later mail
  is dropped too. Switch it off per agent: `sudo 5dive email gate mike inbound off`.
- A first mail TO an address that never wrote to the agent waits for the
  owner's tap (Allow / No). Switch it off: `sudo 5dive email gate mike off`.
- Neither asks about colleagues on the agent's own domain, or anyone on the
  owner's list: `sudo 5dive email allow mike pat@client.com @client.com`.
- At most 50 mails a day per agent (`sudo 5dive email cap mike <n>`).
- Mail is outside text: while the newest message is an email, the agent will
  not run root commands, pay, delete, or change settings or access until the
  owner says yes on their own channel.

Check it: `5dive email status mike`. The DNS and network steps for IT:
[docs/IT-GUIDE.md](docs/IT-GUIDE.md).

Tests (CI runs all three): `bun test tests/email.test.ts` (no dependencies),
`sudo bash tests/cli.sh`, and `cd email && bun install && bun e2e.ts` (the whole
path on one machine).
