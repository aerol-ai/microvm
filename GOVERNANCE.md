# Governance

AerolVM uses a single-maintainer model. The maintainer makes the final decision on project direction, disputes, and releases. A code change reaches the default branch only through a reviewed pull request.

## How decisions are made

- **Direction and disputes.** The maintainer decides. When people disagree about scope, design, or whether a change should land, the maintainer's decision is the project's decision. Discussion happens in the issue or pull request first. Security reports stay on the private path in [SECURITY.md](SECURITY.md).
- **What merges.** A change merges when a [code owner](.github/CODEOWNERS) other than the pull request author approves it and the required status checks pass. The default-branch ruleset dismisses that approval when new commits are pushed and requires approval of the last push before merge. Direct pushes to the default branch are rejected.
- **Releases.** The maintainer publishes official releases and the SDK packages.
- **Access.** A repository administrator reviews anyone before they receive write access, the maintainer role, or release and registry credentials. Those are not granted on request alone.

## Key roles

| Role | Who | Decisions and duties |
| :--- | :--- | :--- |
| Maintainer | [`sumansaurabh`](https://github.com/sumansaurabh) | Final say on direction, disputes, and releases. Approve pull requests. Publish official releases and the SDK packages. Change branch rules, Actions secrets, and security settings. Triage reports sent to [security@aerol.ai](mailto:security@aerol.ai). |
| Code owner | [`sumansaurabh`](https://github.com/sumansaurabh), [`akanshasinha19`](https://github.com/akanshasinha19) | Review pull requests. A code owner other than the author approves a change to the default branch. |
| Write collaborator | [`akanshasinha19`](https://github.com/akanshasinha19), [`sumansaurabh-slice`](https://github.com/sumansaurabh-slice) | Push branches and open pull requests. Official releases stay with the maintainer. |
| Contributor | Anyone else | Open issues and pull requests. No access to Actions secrets, branch rules, or release publishing. |

Who can reach Actions secrets and release publishing is also listed under [Access to sensitive resources](README.md#access-to-sensitive-resources).
