# Ideas Discussions announcement: the open audit witness

Draft only. Post it in the **Ideas** category of `aerol-ai/microvm` Discussions. Wait until the release with the S3 witness is published and its release smoke passes. The Enterprise mode page and the blog post must be live too. The feature ships before it was ever posted as a proposal, so it goes up as an announcement.

---

**Title:** Enterprise mode now works with the free download

**Body:**

### What changed

Enterprise mode (`SB_ENTERPRISE_MODE=true`) makes a server refuse to start unless every strict security rule is in place. One rule is an audit witness: a store off the server that keeps the fingerprints of its audit log. The free download had only a placeholder witness, so enterprise mode always refused to start there.

Now it has a real one. Each server writes its newest fingerprint to an S3 bucket with Object Lock. Object Lock means a stored object cannot be changed or deleted until its lock ends. That holds even for the server that wrote it.

### What you get

- Someone who takes over a server cannot rewrite the history a stored fingerprint covers without being caught. The server refuses to start.
- At every start, the server checks that the bucket is really locked. It writes a test object and tries to delete it the way an attacker would. If that works, it refuses to start.
- `aerolvm audit verify` checks every fingerprint in a window you choose against your exported records. It answers PASS, FAIL or INCOMPLETE.

### What it does not do

- Records written since the last fingerprint (30 seconds by default) can still be rewritten.
- A server that was already taken over when it wrote can store a forged log from the start.
- Servers in a cluster share one cloud role, so one can write into another's place in the bucket. It cannot erase anything, and an alert and the verifier both show it.
- While S3 is down, a server with a witness cannot restart.

### Try it

- Set it up: https://microvm.aerol.ai/enterprise/enterprise-mode/
- Why each check is there: https://microvm.aerol.ai/engineering-audit-witness/

### Questions for you

1. Do you need a store other than AWS S3, such as Google Cloud Storage or Azure?
2. Should an S3 outage keep blocking restarts, or would you rather start and alert?
3. Would you use per-server write limits in the bucket, if they meant a new key layout?

Comment with your answers, or react with a thumbs up if you plan to turn it on.
