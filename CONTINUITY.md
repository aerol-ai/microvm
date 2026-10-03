# Continuity of access

If any one maintainer dies, is incapacitated, or stops supporting AerolVM, the project can still create and close issues, accept proposed changes, and publish a release. A second person already has the permissions those three actions need. No credential handover is required first, so the remaining person can do them within a week of confirmation.

The two accounts that cover each other are [`sumansaurabh`](https://github.com/sumansaurabh) and [`akanshasinha19`](https://github.com/akanshasinha19).

| Action | If `sumansaurabh` is unavailable | If `akanshasinha19` is unavailable |
| :--- | :--- | :--- |
| Create and close issues | [`akanshasinha19`](https://github.com/akanshasinha19) has write access. | [`sumansaurabh`](https://github.com/sumansaurabh) has admin access. |
| Accept a proposed change | [`akanshasinha19`](https://github.com/akanshasinha19) is a [code owner](.github/CODEOWNERS) and approves a pull request opened by someone else. | [`sumansaurabh`](https://github.com/sumansaurabh) is a code owner and approves a pull request opened by someone else. |
| Publish a release | [`akanshasinha19`](https://github.com/akanshasinha19) publishes a GitHub release and can dispatch the SDK publish workflow. | [`sumansaurabh`](https://github.com/sumansaurabh) publishes a GitHub release and can dispatch the SDK publish workflow. |

Publishing a GitHub release starts [`.github/workflows/release.yml`](.github/workflows/release.yml), which builds the release and uploads its assets. Dispatching [`.github/workflows/publish-sdks.yml`](.github/workflows/publish-sdks.yml) publishes the SDK packages. Registry tokens are GitHub Actions secrets. The workflow reads them, so the person publishing does not need a copy of the token.

The default-branch ruleset requires one approval from a code owner who is not the pull request author, and it has no bypass. The remaining code owner accepts a change by approving a pull request that another person opened. [`sumansaurabh-slice`](https://github.com/sumansaurabh-slice) has write access and can open that pull request, as can any contributor.

Day to day, the maintainer publishes official releases. The release permission above is how a release still ships when the maintainer is the person who is unavailable.

[`sumansaurabh`](https://github.com/sumansaurabh) is the only organization owner. Changing branch rules, Actions secrets, and organization billing stays with that role. The three actions in the table do not require it.

## Bus factor

The bus factor is 2. Two people can keep the project from stalling: [`sumansaurabh`](https://github.com/sumansaurabh), the maintainer, and [`akanshasinha19`](https://github.com/akanshasinha19), a code owner who reviews and merges changes onto the default branch. If either one disappears, the other can still accept proposed changes and publish a release, as the table above describes.
