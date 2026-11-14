# email — each agent gets its own email address

People email the agent like a colleague. The mail shows up as a chat; the agent
answers in the same thread, from its own address. 5dive hosts no mail.

Two ways to give an agent an address:

1. **A mailbox your firm already runs**: Microsoft 365 / Outlook, Google
   Workspace, or any IMAP + SMTP server. IT makes `mike@yourfirm.com`, then:
   - **Microsoft 365 / Outlook:**
     `sudo 5dive email connect mike --address=mike@yourfirm.com --provider=microsoft --client-id=<app id>`
     prints a Microsoft link and a short code. Whoever signs in to that mailbox
     types the code there and signs in; run the same command again to finish.
     The sign-in goes through an app your own IT creates once, in your own
     Microsoft account ([docs/IT-GUIDE.md](docs/IT-GUIDE.md)), so no password
     reaches the server and no 5dive account is involved. One app serves
     every agent's mailbox.
   - **Google Workspace or another server:**
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

## Safety

What is checked, on by default, per agent:

- **Is the sender real?** A From line can be faked. Mail counts as from a
  colleague, from someone on the owner's list, or from someone the agent knows
  only when the receiving server confirmed it (SPF, DKIM or DMARC: the sender's
  own domain vouches for it). A mail that cannot be confirmed waits like a
  stranger's, and the owner's card says "it may be faked". A No drops that mail
  and never blocks the real person. Your server's own mail server checks this
  itself; for a firm mailbox, Google's or Microsoft's own check is read.
  Off: `sudo 5dive email gate mike sender off`.
- **Spam** (your server's own mail server): a spam filter running on the server
  (rspamd) puts spam in the agent's spam folder. The agent never reads it, and
  the owner gets no card for it. Off: `sudo 5dive email gate mike spam off`.
  A firm mailbox is filtered by its provider before the agent reads it.
- **Viruses** (your server's own mail server): every mail is scanned on the
  server (ClamAV) before the agent sees it. A mail with a virus is dropped, and
  the owner hears about it once a day in one line, not per mail. With no
  scanner (a server under 4 GB of memory), the agent is told the attachments
  were not scanned. Off: `sudo 5dive email gate mike virus off`.
- **Phishing**: a link that shows one site but goes to another, a look-alike of
  your own domain, or a name that hides another address is flagged to the
  agent, which then opens no links or files from it and tells the owner.
- Nothing is sent to an outside scanner. The filters' signatures update by
  themselves while the server is online, and keep working offline.

The doors, on by default:

- A first mail FROM someone unknown is held on the server. The agent does not
  see it until the owner taps Allow; No deletes it, and that sender's later mail
  is dropped too. Switch it off per agent: `sudo 5dive email gate mike inbound off`.
- A first mail TO an address that never wrote to the agent waits for the
  owner's tap (Allow / No). Switch it off: `sudo 5dive email gate mike off`.
- Neither asks about colleagues on the agent's own domain, or anyone on the
  owner's list: `sudo 5dive email allow mike pat@client.com @client.com`
  (as long as the sender is confirmed, above).
- Cards about new senders come at most once an hour; the rest wait their turn.
  Answering one sends the next at once.
- At most 50 mails a day per agent (`sudo 5dive email cap mike <n>`).
- Mail is outside text: while the newest message is an email, the agent will
  not run root commands, pay, delete, or change settings or access until the
  owner says yes on their own channel.

Check it: `5dive email status mike`. The DNS and network steps for IT:
[docs/IT-GUIDE.md](docs/IT-GUIDE.md).

Tests (CI runs them all): `bun test tests/email.test.ts` (no dependencies),
`sudo env PATH="$PATH" bash tests/cli.sh`, and, with `cd email && bun install`,
`bun e2e.ts` (the whole path on one machine) and `bun e2e-microsoft.ts` (a
Microsoft 365 mailbox against stand-ins for Microsoft's sign-in, IMAP and SMTP).
