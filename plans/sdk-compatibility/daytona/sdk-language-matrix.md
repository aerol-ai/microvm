# Daytona SDK Language Matrix

Daytona compatibility in AerolVM is HTTP-surface based. That means support is primarily determined by which Daytona routes are implemented under `/daytona`, not by a language-specific adapter.

## High-level Daytona SDKs

| Daytona SDK | Upstream path | Status against AerolVM | Notes |
|---|---|---|---|
| Go | `libs/sdk-go` | Partial | Best current reference contract for the AerolVM `/daytona` facade. Works only for implemented control-plane and toolbox routes. |
| Java | `libs/sdk-java` | Partial | Same HTTP compatibility surface as Go. Not separately validated language-by-language. |
| Python | `libs/sdk-python` | Partial | Same HTTP compatibility surface as Go. Not separately validated language-by-language. |
| Ruby | `libs/sdk-ruby` | Partial | Same HTTP compatibility surface as Go. Not separately validated language-by-language. |
| TypeScript | `libs/sdk-typescript` | Partial | Same HTTP compatibility surface as Go. Not separately validated language-by-language. |

## Generated Daytona Client Families

| Daytona client family | Upstream paths | Status against AerolVM | Notes |
|---|---|---|---|
| Control-plane API clients | `libs/api-client-go`, `libs/api-client-java`, `libs/api-client-python`, `libs/api-client-python-async`, `libs/api-client-ruby` | Partial | Works only for the subset of control-plane endpoints and fields implemented under `/daytona`. |
| Toolbox API clients | `libs/toolbox-api-client-go`, `libs/toolbox-api-client-java`, `libs/toolbox-api-client-python`, `libs/toolbox-api-client-python-async`, `libs/toolbox-api-client-ruby` | Partial | Works only for the subset of toolbox routes implemented behind `/daytona/toolbox/{sandboxId}`. |

## Important Interpretation

| Question | Answer |
|---|---|
| Are any Daytona SDK languages fully supported end-to-end? | No. The current status is partial across the board because the AerolVM facade implements only part of the Daytona contract. |
| Are any Daytona SDK languages uniquely unsupported? | No language is singled out. The limitation is the shared HTTP compatibility surface, not the client language. |
| What determines success with a Daytona SDK today? | Whether the code path uses only the supported `/daytona` control-plane and toolbox routes listed in the detailed matrices. |