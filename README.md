# CloudFlare Enumeration Tool

Yet another Cloudflare enumeration script. Compared to other tools it
has the following "benefits":

1. It uses tokens. If you have 2FA (which you should btw), you don't
   need to hack it.
2. It uses the Cloudflare API and doesn't rely on trying to imitate
   users, browsers and what not.
3. It works using Python 3.
4. It tries to keep things clean in your account.

The tool will grab whatever subdomains are available in CloudFront and
put them in a JSON file for further parsing.

## Requirements

This tool uses the Global API token of CloudFront. Instructions to grab
this token are available
[here](https://support.cloudflare.com/hc/en-us/articles/200167836-Where-do-I-find-my-Cloudflare-API-key-#12345682).
*Beware, this token basically grants godlike permissions to the API*

Additionally, you need to do the following.

```
git clone git@github.com:frite/cf-enum.git
cd cf-enum/
pip install -r requirements.txt
python3 cfenum.py -d example.com -o file.json --cf-token TOKEN --cf-email EMAIL
```

## Tool behaviour

The tool will check if a given domain already exists in your account. If
so, it will get the subdomains and exit. If it doesn't exist, it will
automatically add the domain, wait for 30 seconds, grab results and
*remove* the newly created domain.

I am in no way responsible if you manage to break your
Production DNS services. Personally, I avoid using it in production
accounts. Although there hasn't been a case where something broke, the
token has godlike permissions and I prefer to limit impact in case the
token is somehow lost.

Generally, behave responsibly when using this tool.

## Pitfalls

Cloudflare maintains a list of banned domains. Domains that are already
added by other accounts etc. (e.g. google) can't be added. In general,
trying to add such a domain will result in an exception and the tool
will exit.

## Why use this tool?

There was a talk (video [here](https://youtu.be/e_Gq99CKAys) and details [here](https://github.com/appsecco/bugcrowd-levelup-subdomain-enumeration)) discussing this
approach. Although CloudFlare enumeration is not my first approach when
trying to find the attack surface, it is sometimes handy. For this, I
rewrote it to deal with the enumeration in a more sane way, e.g. by
using tokens and not flooding accounts with random stuff.

## Warning
Use this tool responsibly. I am in no way responsible for interruptions
you caused because of using this tool.
