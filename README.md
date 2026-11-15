# 5dive-email

Give each AI agent its own email address, on your own server or in your firm's
mailbox. A [5dive](https://5dive.com) plugin.

```
sudo 5dive plugin add 5dive-ai/5dive-email
sudo 5dive email connect mike --address=mike@yourfirm.com --provider=google --task=<DIVE-N>
```

Microsoft 365 / Outlook: `--provider=microsoft --client-id=<your firm's app>`.
It signs in with a Microsoft code, through an app your own IT creates in your
own Microsoft account. No password, and no 5dive account in between.

Or run the mail on your server: `sudo 5dive email server setup --domain=ai.yourfirm.com`,
then `sudo 5dive email connect mike --self-hosted`.

Mail arrives as a chat, and the agent answers in the same thread. A first mail
from someone new, and a first mail to someone new, each wait for your Allow.

What it does and how to set it up: [email/README.md](email/README.md). The DNS
and network steps for IT: [email/docs/IT-GUIDE.md](email/docs/IT-GUIDE.md).

MIT licensed.
