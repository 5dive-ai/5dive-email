# Email for your AI employees — IT guide

## A. Use a mailbox you already run

1. Create a normal mailbox for the agent (e.g. `mike@yourfirm.com`).
2. Allow IMAP and SMTP sign-in for that one mailbox.
   - **Google Workspace:** turn on 2-step verification for the mailbox and make
     an app password (Google Account > Security > App passwords).
   - **Microsoft 365 / Outlook:** no password. The agent signs in through an
     app you create once in your own Microsoft account: see "Microsoft 365"
     below.
   - **Any other server:** IMAP on 993 (TLS) and SMTP submission on 587 or 465.
3. The owner runs `sudo 5dive email connect <agent> --address=<a>
   --provider=google|other [--imap-host=… --smtp-host=…] --task=<DIVE-N>`
   and pastes the password into the one-time link.

## Microsoft 365 / Outlook

Microsoft turned off password sign-in for IMAP and SMTP in 2022. The agent
signs in with Microsoft's own sign-in instead. Two ways:

- **5dive's Microsoft app (the default, nothing to set up).** `connect
  --provider=microsoft` with no `--client-id`. The person signing in sees 5dive's
  app asking to read and send mail as that mailbox. The token stays on your
  server; mail goes only between your server and Microsoft. If your tenant lets
  users consent only to admin-approved apps, connect prints the one link a
  Global or Cloud Application Administrator opens to approve it for the firm.
  End the access in Entra > Enterprise applications (or myapps.microsoft.com).
  IMAP and Authenticated SMTP must be on for the mailbox (below, step 2);
  connect checks both and says which one is off.
- **Your own sign-in app (once, about 5 minutes).** For a firm that allows no
  outside app, or an offline box: the app lives in YOUR Microsoft account, with
  no 5dive app in between. One app serves every agent's mailbox in your firm.

**1. Create the app.** In the Microsoft Entra admin center (entra.microsoft.com):

1. App registrations > New registration. Name: `AI employees email`.
   Supported account types: "Single tenant only" (this organization only).
   Redirect URI: platform **Public client/native (mobile & desktop)**, value
   `https://login.microsoftonline.com/common/oauth2/nativeclient`. Register.
2. Copy the **Application (client) ID** and the **Directory (tenant) ID**.
3. Authentication > "Allow public client flows": **Yes**. Save. (Only the
   `--device-code` sign-in below needs it; it does no harm otherwise.)
4. API permissions > Add a permission > Microsoft Graph > Delegated permissions:
   `IMAP.AccessAsUser.All`, `SMTP.Send`, `offline_access`, `openid`, `email`.
   Then **Grant admin consent** for your organization.

Or the same in one go with the Azure CLI (as an admin):

```
az login --allow-no-subscriptions
APP=$(az ad app create --display-name "AI employees email" --sign-in-audience AzureADMyOrg \
      --is-fallback-public-client true \
      --public-client-redirect-uris https://login.microsoftonline.com/common/oauth2/nativeclient \
      --query appId -o tsv)
az ad app permission add --id "$APP" --api 00000003-0000-0000-c000-000000000000 --api-permissions \
  652390e4-393a-48de-9484-05f9b1212954=Scope 258f6531-6087-4cc4-bb90-092c5fb3ed3f=Scope \
  7427e0e9-2fba-42fe-b0c0-848c9e6a8182=Scope 37f7f235-527c-4136-accd-4a02d197296e=Scope \
  64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0=Scope
az ad sp create --id "$APP"
az ad app permission admin-consent --id "$APP"
echo "client id: $APP   tenant id: $(az account show --query tenantId -o tsv)"
```

(The five ids are IMAP.AccessAsUser.All, SMTP.Send, offline_access, openid and
email.)

**2. Let the agent's mailbox use IMAP and sending.** The mailbox needs a
license with Exchange Online (Business Basic or Exchange Online Plan 1 is
enough). New Microsoft 365 accounts switch sending by sign-in (SMTP AUTH) off,
so switch it on for that one mailbox: Microsoft 365 admin center > Users >
the agent > Mail > Manage email apps > tick **IMAP** and **Authenticated
SMTP**. Or in Exchange Online PowerShell:

```
Set-CASMailbox -Identity mike@yourfirm.com -ImapEnabled $true -SmtpClientAuthenticationDisabled $false
```

The agent's mailbox signs in like any person in your firm, so it needs its
second factor set up (Microsoft asks at its first sign-in when security
defaults are on): keep that authenticator with whoever looks after the
mailbox.

**3. Connect.** The owner runs
`sudo 5dive email connect mike --address=mike@yourfirm.com --provider=microsoft --client-id=<Application id> --tenant=<Directory id>`.
It prints a Microsoft sign-in link. Whoever holds the agent mailbox's sign-in
opens it, signs in as `mike@yourfirm.com` and accepts. Microsoft then shows an
empty page: they copy the whole address from the browser's address bar and
send it to the owner within 10 minutes, who finishes with
`sudo 5dive email connect mike --provider=microsoft --code='<that address>'`.
The code in that address works once, for minutes, and only on this server (it
needs a secret that never leaves it). The server checks that the account that
signed in IS the agent's mailbox, and refuses any other.

Why a link and not a short code: Microsoft's security defaults, on in most
small tenants, refuse the short-code ("device code") sign-in for every user
(error 530035), and only a paid Conditional Access licence can exempt one app.
If your policies allow it, `--device-code` prints `https://microsoft.com/devicelogin`
and a code to type instead; run the same command again to finish.

What stays on the server: a Microsoft sign-in token for that one mailbox, in
the agent's own settings file, readable only by the agent. No password.

**To end the access:** `sudo 5dive email disconnect mike` deletes the token.
From your side: delete the app, revoke the mailbox's sessions (Entra > Users >
the agent > Revoke sessions), or change its password. The owner is then told
the agent can no longer read the mailbox, and how to sign in again.

On an offline (local-only) server, a mail server on your office network works
as it is. A cloud mailbox needs: `sudo 5dive config local-only allow email`.

## B. Run the mail on this server

1. Pick a domain or subdomain for the agents, e.g. `ai.yourfirm.com`.
2. `sudo 5dive email server setup --domain=ai.yourfirm.com`
   By default the server sends mail itself, signed with its own DKIM key. That
   works from an established server. A NEW cloud account often blocks sending
   on port 25 until you ask the host (Hetzner until the first paid invoice,
   DigitalOcean and Vultr until you open a support ticket). Setup checks this
   for you and stops if it is blocked (`sudo 5dive email server check` runs the
   same check alone; it never sends mail). Then ask the host to open it, use
   the firm's own mailbox (part A), or send through a relay:
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
