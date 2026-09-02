# Authelia — scope request, and why it was not sent from here

**Status: NOT SENT. Blocked by Authelia's own policy, not by a missing account.**

Authelia was picked as a first public case-study candidate because
[`SECURITY.md`](https://github.com/authelia/authelia/blob/master/SECURITY.md) has a **Help wanted**
section naming *Code Security Audit / Analysis* and *Penetration Testing*. Reading the section
carefully changes the picture, and reading their AI policy changes it again.

## 1. The "Help wanted" section is a request for sponsorship, not an open invitation

Quoted from `SECURITY.md`:

> We are actively looking for **sponsorship** to obtain security audits […] If you know of a company
> which either performs these kinds of audits and would be willing to **sponsor the audit** in some
> way such as doing it pro bono or at a discounted rate […] then please feel free to contact us.

That asks for someone to **fund or donate a professional audit**. It is not a standing authorisation
for individuals to point tooling at the project. Treating it as one would be exactly the
over-reading the plan warned against.

## 2. Their Artificial Intelligence policy forbids the message we were going to send

[`docs/content/policies/artificial-intelligence.md`](https://www.authelia.com/policies/artificial-intelligence/),
General Policy, rule 4:

> **The areas where humans are intended to communicate with each other should be absent from
> artificial intelligence generated content** i.e. you should not be using artificial intelligence to
> create or reply to emails, issues, discussions, chat rooms, etc.

Rule 5:

> Deliberate attempts to hide, subvert, or mislead anyone about the use of artificial intelligence
> are strictly prohibited and will be considered an immediate violation of this policy, and have a
> **reasonable likelihood of being treated as a deliberate malicious act**.

The outreach message in the launch plan is AI-drafted and would have been AI-posted. Sending it —
disclosed or not — violates rule 4 directly, and sending it undisclosed lands in rule 5. Their
`SECURITY.md` separately requires full disclosure of any generative-AI involvement in *discovering*
or *reporting* a vulnerability, which a SecHelix-assisted review would obviously trigger.

**So the assistant did not contact them.** No issue, no discussion, no email, no chat message.

## 3. What a human maintainer can do instead

None of this rules Authelia out. It rules out *an agent* opening the conversation. If Omar wants to
pursue it, the message has to be written and sent by him, in his own words, and it should say
plainly that SecHelix is an AI-assisted tool. A starting point — **to be rewritten in his own
voice, not pasted**:

- who he is and that SecHelix is his open-source, AI-assisted AppSec tooling;
- that he read the AI policy and is disclosing AI involvement up front, as rule 3 requires;
- that he is *not* reporting a vulnerability, he is asking whether a bounded review is welcome;
- the proposed bounds: a pinned public commit, static/code review first, local-only dynamic tests
  if and only if they say yes, nothing against production or third-party infrastructure;
- private disclosure through GitHub Security Advisories or `security@authelia.com`, never a public
  issue;
- that nothing is published before their disclosure process completes, and that a redacted case
  study would only follow with explicit permission.

The right channel for the *scope question* is a GitHub Discussion or the chat options in their
contact page — **not** the security advisory form, which is for actual vulnerability reports.

## 4. Criteria for picking a different target

The trophy-case requirement is one **accepted public fix** with authorization, a pinned commit, a
verified finding, maintainer correspondence, a public patch, a regression test and permission to
attribute. A candidate qualifies only if all of these hold:

1. The project explicitly invites external security review **from individuals**, not just audit
   sponsorship.
2. Its contribution and security policies permit AI-assisted work, with disclosure.
3. It has a documented private disclosure channel.
4. It is small enough that a bounded static review can produce something real.

Authelia fails (2) for agent-sent communication and is ambiguous on (1). Any replacement must be
checked against all four **before** the first message, and the check must be recorded here.
