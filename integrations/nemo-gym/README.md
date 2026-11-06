# aerolvm-nemo-gym

A sandbox provider for [NVIDIA NeMo Gym](https://github.com/NVIDIA-NeMo/Gym)
that runs every NeMo Gym sandbox as an AerolVM sandbox. NeMo Gym finds it by
itself under the name `aerolvm`.

## Install

NeMo Gym's provider system is newer than its latest PyPI release (0.4.0), so
install NeMo Gym from GitHub (it needs Python 3.14), then this package:

```bash
pip install "nemo-gym @ git+https://github.com/NVIDIA-NeMo/Gym.git"
pip install "git+https://github.com/aerol-ai/microvm.git#subdirectory=integrations/nemo-gym"
```

Set `SB_API_URL` and `SB_PAT_TOKEN` so the provider can reach your AerolVM
server.

## Use it

Pass [`configs/aerolvm.yaml`](configs/aerolvm.yaml) where you would pass
another provider's config. The agent's config does not change:

```bash
gym env start \
    --config responses_api_agents/mini_swe_agent_2/configs/mini_swe_agent_2.yaml \
    --config /path/to/integrations/nemo-gym/configs/aerolvm.yaml \
    --config responses_api_models/vllm_model/configs/vllm_model.yaml
```

Config keys under `sandbox: aerolvm:`:

| Key | Default | What it does |
| --- | --- | --- |
| `api_url`, `api_token`, `team` | `SB_API_URL`, `SB_PAT_TOKEN`, `SB_TEAM` | Where the server is |
| `default_image` | `python:3.12-slim` | Image when the agent's spec names none |
| `create_options` | `{}` | Other `MicroVM.create` fields for every sandbox, such as `runtime` or `networkBlockAll` |
| `exec_timeout_s` | `180` | Command time limit when the agent gives none |
| `probe_deadline_s` | `60` | How long a new sandbox may take to run its first command (0 skips the check) |

## How it maps

| NeMo Gym | AerolVM |
| --- | --- |
| `create(spec)` | `MicroVM.create` with the spec's image, env, CPU, memory and disk; metadata becomes tags (plus `integration=nemo-gym`, and an `aerolvm-create-op` tag of its own that finds the sandbox when a create fails with no clear answer); `ttl_s` becomes `lifecycle.destroyAtAge`; `workdir` is made. Returns once a probe command runs; a failed probe destroys the sandbox, and so does a create cancelled while the sandbox is being made. |
| `exec` | `exec` with `workDir`, `env` and `timeoutSeconds`; a timed-out command returns code 124 |
| `upload_file`, `download_file`, `write_file`, `read_file` | `upload_file`, `download_file_to`, `download_file` |
| `status` | `get`, mapped to NeMo Gym's statuses (a missing sandbox is `stopped`) |
| `close` | `destroy` (a sandbox that is already gone is fine) |

NeMo Gym's own Daytona provider also works against AerolVM's Daytona layer
(set `DAYTONA_API_URL` to your server's address plus `/daytona`). This
provider adds AerolVM's own features: tags, `ttl_s` as a self-delete age,
and any create option such as the runtime. The docs page "NVIDIA NeMo Gym"
compares the two.

## Limits

- Commands run as the sandbox's user; another user per command is refused.
  Set `create_options.osUser` instead.
- GPU requests and sidecar containers are refused before a sandbox is made.
- Each upload holds the whole file in memory.

## Tests

The tests run offline against NeMo Gym's own provider types, registry and
`AsyncSandbox`, with a fake AerolVM client that runs commands on your own
machine. NeMo Gym is installed without its training-stack dependencies,
which the provider API never imports:

```bash
cd integrations/nemo-gym
python3.14 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-ci.txt
.venv/bin/pip install --no-deps --no-build-isolation --require-hashes -r requirements-ci-nodeps.txt
.venv/bin/pip install --no-deps -e ../../sdk/python -e .
.venv/bin/python -m unittest discover -s tests -v
```
