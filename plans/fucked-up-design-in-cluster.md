
❯ So the SDK does not know the right IP. It does not need to. Any node can receive API traffic, because sandboxd uses the replicated cluster  
  placement map and forwards API requests to the owner node.                                                                                  
                                                                                                                                              
  That part is handled in the server code around clusterForwardWrap (line 20).                                                                
                                                                                                                                              
  The problem is not SDK/API traffic. The problem is public sandbox URLs.                                                                     
                                                                                                                                              
  Example:                                                                                                                                    
                                                                                                                                              
  text                                                                                                                                        
                                                                                                                                              
                                                                                                                                              
                                                                                                                                              
  https://<sandbox-id>.sandbox.example.com                                                                                                    
                                                                                                                                              
                                                                                                                                              
                                                                                                                                              
  If that DNS round-robins to node B but the sandbox lives on node C, node B’s Caddy does not know that sandbox route. Today it will likely   
  return 404. The cluster does not currently forward Caddy sandbox URL traffic across nodes.                                                  
                                                                                                                                              
  So:                                                                                                                                         
                                                                                                                                              
  text                                                                                                                                        
                                                                                                                                              
                                                                                                                                              
                                                                                                                                              
  SDK/API calls                         OK with DNS round-robin                                                                               
  sandbox.publicURL in browser          NOT reliable with DNS round-robin                                                                     
  exposed HTTP port URLs                NOT reliable with DNS round-robin                                                                     
                                                                                                                                              
                                                                                                                                              
                                                                                                                                              
  Your DNS setup with 3 A records is acceptable only if your main usage is SDK calls like create, exec, file upload/download, sessions,       
  lifecycle, etc.                                                                                                                             
                                                                                                                                              
  If your product depends on users opening sandbox URLs reliably, then DNS round-robin is the wrong setup. You need one of these:             
                                                                                                                                              
  Single-node deployment for now.                                                                                                             
  Per-sandbox DNS: <sandbox-id>.sandbox.example.com -> owner-node-ip.                                                                         
  Smarter SNI-aware ingress that routes each sandbox hostname to the owner node.                                                              
  Add cross-node sandbox URL proxying to the product.                                                                                         
                                                                                                                                              
  So your mental model is correct: DNS itself cannot know where the sandbox lives. The cluster solves that for the API plane, but not yet for 
   the public sandbox URL data plane. This is what I got from another agent, and it feels like you fucked up the design for the cluster. Can  
  you tell me? What are the solutions for this particular scenario? How will my sandbox be accessible?                                        

  Searched for 3 patterns, read 3 files, listed 4 directories (ctrl+o to expand)

⏺ You haven't fucked up the design. You documented this exact seam in setup/cluster.md:431-518 and setup/cluster.md:871-893. The other agent
  is just restating what you wrote. The split is deliberate:

  - API plane (one hostname, any node serves) → solved by cluster.ForwardHTTP (internal/cluster/forward.go:75) wrapping every per-sandbox
  route at pkg/api/v1/cluster_handler.go:30. Trivially horizontal.
  - Data plane (<id>.sandbox.example.com) → bound to the node where the container actually exists, because the container, host port, and Unix
  socket are local-only state. No amount of cleverness changes that.

  The question is just: how does the connection reach the owner node? Five options, ordered by effort:

  1. Per-sandbox DNS (Topology B in your doc). Webhook on placement change → Cloudflare API writes <id>.sandbox.example.com → <owner-IP>.
  ~100ms write, one record per sandbox. Failover takes one TTL (set 30–60s). Easy to ship — you already have the placement event stream in
  raft. Downside: Cloudflare rate limits at very high churn (~1200 ops/5min/zone on free, much higher on paid), and DNS resolution can be
  cached by buggy resolvers past TTL.

  2. Cross-node Caddy stub routes. This is the one your doc dismissed too quickly. Every node's Caddy gets a route per non-local sandbox that
  reverse-proxies (or caddy-l4 passes-through by SNI) to the owner. The placement map is already replicated to every node by raft, and
  pkg/caddy/client.go already has UpsertTLSSNIRoute — you'd add a reconciler that, on placement change, syncs each node's Caddy with
                                                                                                                                              
                                                                                                                                              
  SDK/API calls                         OK with DNS round-robin                                                                               
  sandbox.publicURL in browser          NOT reliable with DNS round-robin                                                                     
  exposed HTTP port URLs                NOT reliable with DNS round-robin                                                                     
                                                                                                                                              
                                                                                                                                              
                                                                                                                                              
  Your DNS setup with 3 A records is acceptable only if your main usage is SDK calls like create, exec, file upload/download, sessions,       
  lifecycle, etc.                                                                                                                             
                                                                                                                                              
  If your product depends on users opening sandbox URLs reliably, then DNS round-robin is the wrong setup. You need one of these:             
                                                                                                                                              
  Single-node deployment for now.                                                                                                             
  Per-sandbox DNS: <sandbox-id>.sandbox.example.com -> owner-node-ip.                                                                         
  Smarter SNI-aware ingress that routes each sandbox hostname to the owner node.                                                              
  Add cross-node sandbox URL proxying to the product.                                                                                         
                                                                                                                                              
  So your mental model is correct: DNS itself cannot know where the sandbox lives. The cluster solves that for the API plane, but not yet for 
   the public sandbox URL data plane. This is what I got from another agent, and it feels like you fucked up the design for the cluster. Can  
  you tell me? What are the solutions for this particular scenario? How will my sandbox be accessible?                                        

  Searched for 3 patterns, read 3 files, listed 4 directories (ctrl+o to expand)

⏺ You haven't fucked up the design. You documented this exact seam in setup/cluster.md:431-518 and setup/cluster.md:871-893. The other agent
  is just restating what you wrote. The split is deliberate:

  - API plane (one hostname, any node serves) → solved by cluster.ForwardHTTP (internal/cluster/forward.go:75) wrapping every per-sandbox
  route at pkg/api/v1/cluster_handler.go:30. Trivially horizontal.
  - Data plane (<id>.sandbox.example.com) → bound to the node where the container actually exists, because the container, host port, and Unix
  socket are local-only state. No amount of cleverness changes that.

  The question is just: how does the connection reach the owner node? Five options, ordered by effort:

  1. Per-sandbox DNS (Topology B in your doc). Webhook on placement change → Cloudflare API writes <id>.sandbox.example.com → <owner-IP>.
  ~100ms write, one record per sandbox. Failover takes one TTL (set 30–60s). Easy to ship — you already have the placement event stream in
  raft. Downside: Cloudflare rate limits at very high churn (~1200 ops/5min/zone on free, much higher on paid), and DNS resolution can be
  cached by buggy resolvers past TTL.

  2. Cross-node Caddy stub routes. This is the one your doc dismissed too quickly. Every node's Caddy gets a route per non-local sandbox that
  reverse-proxies (or caddy-l4 passes-through by SNI) to the owner. The placement map is already replicated to every node by raft, and
  pkg/caddy/client.go already has UpsertTLSSNIRoute — you'd add a reconciler that, on placement change, syncs each node's Caddy with
  (sandbox_id → owner_internal_IP) for sandboxes it doesn't own. Cost: one extra east-west hop on (N-1)/N requests; trivial inside a VPC. This
   is the cheapest "real" fix and stays inside sandboxd.

  3. SNI-aware L7 ingress (Envoy + xDS). Replace the NLB with Envoy fed by a control loop that polls /v1/cluster/members + placements and
  rewrites the SNI→backend map. Cleanest production answer, but you're now operating Envoy.

  4. Single ingress node. One sandboxd runs only as router (option 2 with zero local sandboxes). Shifts the HA problem to that one node — not
  really a solution, just a topology variant.

  5. Anycast. Needs BGP. Skip.

  My recommendation: ship option 2 as a new feature in pkg/caddy + a placement watcher in internal/cluster. It removes the asterisk from your
  cluster docs without forcing operators onto Envoy or per-sandbox DNS, and the whole thing is ~a few hundred lines because the inputs
  (placement map, Caddy admin API, peer API URLs) all already exist in this repo. The user-visible win: any node can serve any sandbox URL,
  matching the API-plane property — which is what people expect when they see "cluster."

  Short-term workaround for users today: option 1 via webhook, or single-node until 2 lands.

  Want me to sketch the implementation plan for option 2?

✻ Baked for 1m 32s

❯ i do not understand at all help me understand each option in more detail. In a single-node setup, when the node becomes available, I can    
  open the port for the sandbox for HTTP, HLS, and HLS+SNP and TCP. Will it be possible with the cluster approach? If someone is calling      
  Sandbox.example.com and it tries to write, it creates a sandbox. If it tries to write a file in it, will it end up in the correct sandbox   
  every time? If I try to open an HTTP port or TCP port or UDP port, will that work everytime. This is the perspective I am asking you to     
  build, and now explain to me each of these options and then tell me how it will solve it. Right now I am not able to understand, so you     
  need to help me understand it in depth.                                                                                                     

  Searched for 1 pattern (ctrl+o to expand)

⏺ Good — let me build this from the ground up. I'll walk through what actually happens at the network layer for each request type, then map
  each option onto your concrete questions.

  Part 1: The mental model — two completely different traffic types

  Your sandbox, once running, has two different kinds of public traffic hitting it. They look similar (both go through HTTPS on port 443) but
  they are routed by completely different mechanisms.

  Type A — API traffic (the SDK / sandbox.example.com)

  SDK call: sb.files.write("/app/main.py", "...")
              │
              ▼
  HTTP POST https://sandbox.example.com/v1/sandboxes/abc123/files/...
              │
              ▼  TCP/TLS connection lands on SOME node (DNS or LB picks)
              ▼
  Caddy on that node: "host = sandbox.example.com → API"
              │
              ▼
  sandboxd HTTP handler: "path has {id}=abc123. Where does abc123 live?"
              │
              ▼  c.OwnerOf("abc123") → reads raft FSM in memory
              │
              ▼
  Owner is node-C → reverse-proxy the entire HTTP request to node-C:21212
              │
              ▼
  Node-C's sandboxd gets the request, sees it owns abc123, executes locally
              │
              ▼
  Response streams back through node-A → client

  The key magic: the placement map (abc123 → node-C) is replicated to every node by raft. So every node knows where every sandbox lives. When
  a request arrives that the local node doesn't own, sandboxd's HTTP handler reverse-proxies it. This is clusterForwardWrap in
  pkg/api/v1/cluster_handler.go:30 calling cluster.ForwardHTTP in internal/cluster/forward.go:75.

  This is application-layer routing. sandboxd reads the URL path, looks up {id}, and forwards in Go code. Caddy doesn't know or care about
  which sandbox the request is for.

  Type B — Sandbox URL traffic (the data plane)

  When a user opens a port on their sandbox, you mint one of three things depending on protocol:

  ┌──────────┬───────────────────────────────────────────────────────────────┬──────────────────────────────────────────────────┐
  │ Protocol │                       What gets opened                        │                URL/endpoint shape                │
  ├──────────┼───────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
  │ http     │ A Caddy HTTP route on <id>.sandbox.example.com → container IP │ https://abc123.sandbox.example.com               │
  ├──────────┼───────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
  │ tls      │ An entry in caddy-l4's SNI mux → container IP:port            │ <id>-<port>.sandbox.example.com:443 (SNI-routed) │
  ├──────────┼───────────────────────────────────────────────────────────────┼──────────────────────────────────────────────────┤
  │ tcp      │ A raw TCP listener on a host port from the pool               │ node-public-IP:23456                             │
  └──────────┴───────────────────────────────────────────────────────────────┴──────────────────────────────────────────────────┘

  Now look at what each one needs to land:

  Browser opens https://abc123.sandbox.example.com
              │
              ▼  DNS resolves → ??? whichever node DNS picks
              ▼
  TCP/TLS connection lands on node-A
              │
              ▼
  Caddy on node-A: "host = abc123.sandbox.example.com → ???"
              │
              ▼
  node-A's Caddy ONLY HOLDS ROUTES FOR SANDBOXES IT OWNS.
              │
              ▼  If abc123 lives on node-C: route doesn't exist on node-A
              ▼
  404 / connection drops

  Here's the difference: Caddy is configured by the local sandboxd at the moment the sandbox is created on that node. Node-A's sandboxd never
  tells node-A's Caddy "by the way, abc123 lives on node-C." Today, each node's Caddy is an island that only knows about its own local
  sandboxes.

  This is the asymmetry. The API-plane has a software shim (clusterForwardWrap) that knows the whole placement map. The data-plane has Caddy,
  which doesn't.

  ---
  Part 2: Your specific questions, answered against today's code
  
  ▎ "If someone is calling sandbox.example.com to write, will the file end up in the right sandbox every time?"

  Yes, always. This is the API plane (Type A). The SDK call is POST /v1/sandboxes/abc123/files/.... The connection can land on any node —
  clusterForwardWrap reads abc123, looks up the owner in the in-memory FSM, and forwards. There is no scenario where a write to sandbox abc123
   lands in a different sandbox, because every node has the same placement map and the routing is by sandbox ID, not by network locality.

  ▎ "If I open an HTTP port — <id>.sandbox.example.com — will it work every time?"

  Only when DNS happens to land on the owner. This is Type B. With 3 nodes behind round-robin DNS / NLB, ~33% of connections reach the owner
  and serve correctly. The other ~67% land on a non-owner Caddy that has no route for <id>.sandbox.example.com and returns 404.

  ▎ "If I open a TLS port (HTTPS+SNI) — <id>-<port>.sandbox.example.com:443 — will it work every time?"

  Same answer — only when DNS lands on the owner. caddy-l4's SNI route exists only on the owner node. Non-owner nodes don't have it.

  ▎ "If I open a TCP port — <node-IP>:23456 — will it work every time?"

  Yes, always — but with a catch. TCP exposures don't go through DNS at all. The ExposePortResponse returns node-public-IP:port directly. The
  client connects straight to that IP. So it works 100% of the time as long as the client uses the URL the API gave them. The catch: on 
  failover, the IP changes (sandbox moves to a new node) AND the host port may change (new owner picks a fresh port from its local pool). The
  URL the client cached is dead. They must re-fetch.

  ▎ UDP?

  Not supported. Look at pkg/models/types.go:362 — ValidExposedPortProtocol only accepts http, tcp, tls. UDP would need new code in pkg/caddy
  and either caddy-l4 UDP support or a different listener.

  So: the API plane is bulletproof. The HTTP/TLS sandbox-URL planes are 1/N reliable. The TCP plane is reliable but not subdomain-based.

  ---
  Part 3: The five options, explained from the network layer up
  
  For each option I'll trace what happens when a browser opens https://abc123.sandbox.example.com and abc123 lives on node-C.

  Option 1 — Per-sandbox DNS (Topology B)

  The change: When sandbox abc123 is created on node-C, sandboxd makes an API call to your DNS provider (Cloudflare): "create A record
  abc123.sandbox.example.com → node-C-public-IP." On failover, sandboxd updates that record.

  What happens at request time:
  Browser: https://abc123.sandbox.example.com
              │
              ▼  DNS query → returns node-C's IP (specific to this sandbox)
              ▼
  TCP connection goes DIRECTLY to node-C
              │
              ▼
  node-C's Caddy: "host = abc123.sandbox.example.com → local container" ✓
              │
              ▼
  200 OK
  
  Why it works: DNS itself becomes the routing layer. Each sandbox has its own DNS record pointing at its current owner. The connection never
  lands on the wrong node because DNS already resolved to the right one.

  Solves:
  - HTTP sandbox URLs: ✓ every time
  - TLS sandbox URLs: ✓ every time (same SNI hostname → same DNS record)
  - TCP host:port URLs: already worked; unchanged

  Costs:
  - One DNS write per sandbox create (~100-300ms via Cloudflare API).
  - DNS propagation lag on failover — typically TTL seconds (set 30-60s) of downtime when the sandbox moves.
  - Cloudflare API rate limits: free tier ~1200 record ops per 5 min per zone. Paid is much higher but not infinite. If you create thousands
  of sandboxes per minute, you can starve.
  - Operator dependency: every cluster operator must have a programmable DNS provider with credentials in sandboxd.
  - Provider lock-in: you'd ship a Cloudflare driver, then a Route53 driver, etc. Or expose a webhook and let operators wire their own.

  Effort: Small. Add a DNSProvider interface, a Cloudflare implementation, and call it from the placement-event stream.

  ---
  Option 2 — Cross-node Caddy stub routes (my recommendation)
  
  The change: Every node's Caddy has a route for every sandbox in the cluster, not just the local ones. For local sandboxes the route points
  to the local container. For remote sandboxes the route points to the owner node's internal IP on port 443, with TLS pass-through (or to the
  owner's Caddy admin endpoint over the private network).

  The placement map is already replicated to every node by raft. You just need a reconciler in pkg/caddy that, on every placement change,
  syncs the local Caddy:

  For each sandbox in placement_map:
    if owner == this_node:
      UpsertHTTPRoute(<id>.sandbox.example.com → local container IP:port)
    else:
      UpsertHTTPRoute(<id>.sandbox.example.com → owner_internal_IP:443) [pass-through]

  What happens at request time (when DNS picks node-A but owner is node-C):
  Browser: https://abc123.sandbox.example.com
              │
              ▼  DNS round-robin → lands on node-A
              ▼  
  node-A's Caddy: "host = abc123.sandbox.example.com → node-C:443" ✓
              │
              ▼  TCP/TLS pass-through (caddy-l4) to node-C
              ▼
  node-C's Caddy: "host = abc123.sandbox.example.com → local container" ✓
              │
              ▼
  200 OK
  
  Why it works: Every node becomes a router for every sandbox. The placement map (which every node already has) is now reflected in every
  node's Caddy config.

  Solves:
  - HTTP sandbox URLs: ✓ every time
  - TLS sandbox URLs: ✓ every time (caddy-l4's SNI mux gets a stub entry per non-local sandbox; pass-through preserves the original TLS
  handshake to the owner)
  - TCP host:port URLs: needs separate work — TCP doesn't have SNI to demux on, so you'd need a host port → owner reverse proxy on each node,
  OR keep TCP URLs as direct-to-owner-IP (status quo).

  Costs:
  - One extra east-west TCP hop on (N-1)/N requests. Inside a VPC this is sub-millisecond and free.
  - Caddy config size scales with total_sandboxes × nodes. For 10K sandboxes × 5 nodes = 50K route entries. Caddy can handle this but memory
  grows.
  - Reconciler complexity: must stay in sync with raft placement events, retry on Caddy admin API failures, handle the case where the owner
  has changed mid-flight.
  - TLS pass-through means the entry node never sees the request body (good for privacy, neutral for performance).

  Effort: Medium. Most of the pieces exist (pkg/caddy/client.go has Upsert/Delete; raft has placement events). New code is a watcher +
  reconciler.

  ---
  Option 3 — SNI-aware L7 ingress (Envoy / HAProxy out front)
  
  The change: Replace the AWS NLB with a layer-7 proxy (Envoy) that knows which backend each <id>.sandbox.example.com lives on. A small
  control-plane process polls sandboxd's /v1/cluster/members + placement map and pushes config to Envoy via xDS (or rewrites HAProxy config
  and reloads).

  What happens at request time:
  Browser: https://abc123.sandbox.example.com
              │
              ▼  DNS → Envoy
              ▼  
  Envoy reads SNI = abc123.sandbox.example.com
              │
              ▼  Looks up: abc123 → node-C
              ▼  TCP pass-through to node-C
              ▼  
  node-C's Caddy: local route ✓ → container ✓

  Solves: Same as Option 2, plus the routing decision is centralized so you don't have N copies of the placement map driving N Caddys.

  Costs:
  - You're now operating Envoy or HAProxy. This is real ops surface: config push, health checks, version upgrades, observability.
  - Single point of failure in front of the cluster (mitigate with multiple Envoys + L4 LB in front of those, but now you have two ingress
  tiers).
  - The control-plane process is your code, must be HA, must reconcile correctly.
  - Operator burden: this is no longer "run install.sh on 3 boxes." Now operators must deploy and run Envoy too.

  Effort: Large. Best fit for a managed service offering (you run the cluster), poor fit for self-hosted.

  ---
  Option 4 — Single ingress node
  
  The change: Designate one node as "ingress only." It runs sandboxd with Caddy but never owns sandboxes. Its Caddy holds a route to every
  sandbox's owner (basically Option 2, but only on this one node). All public DNS points at this node.

  What happens at request time: Same as Option 2, but only one node knows the routes.

  Solves: Same as Option 2.

  Costs:
  - The ingress node is a SPOF. If it dies, all data-plane traffic fails (API still works because clients can hit other nodes directly… if
  they know the IPs, which they don't because DNS points here).
  - All east-west traffic funnels through one node — bandwidth bottleneck and a tempting DDoS target.
  - Doesn't really save you anything over Option 2; it's the same code with worse availability.

  Effort: Small (subset of Option 2). But not recommended.

  ---
  Option 5 — Anycast / BGP
  
  The change: Each node advertises the same public IP via BGP. The internet's routing fabric picks the nearest node.

  Why it doesn't help your problem: Anycast picks a node by network proximity, not by which sandbox lives where. You'd still have the
  wrong-node problem 1/N of the time, plus you'd need to run BGP. Skip.
  wrong-node problem 1/N of the time, plus you'd need to run BGP. Skip.

  ---
  Part 4: How each option answers your concrete questions

  - Single point of failure in front of the cluster (mitigate with multiple Envoys + L4 LB in front
  of those, but now you have two ingress tiers).
  - The control-plane process is your code, must be HA, must reconcile correctly.
  - Operator burden: this is no longer "run install.sh on 3 boxes." Now operators must deploy and run
   Envoy too.

  Effort: Large. Best fit for a managed service offering (you run the cluster), poor fit for
  self-hosted.

  ---
  Option 4 — Single ingress node

  The change: Designate one node as "ingress only." It runs sandboxd with Caddy but never owns
  sandboxes. Its Caddy holds a route to every sandbox's owner (basically Option 2, but only on this
  one node). All public DNS points at this node.

  What happens at request time: Same as Option 2, but only one node knows the routes.

  Solves: Same as Option 2.

  Costs:
  - The ingress node is a SPOF. If it dies, all data-plane traffic fails (API still works because
  clients can hit other nodes directly… if they know the IPs, which they don't because DNS points
  here).
  - All east-west traffic funnels through one node — bandwidth bottleneck and a tempting DDoS target.
  - Doesn't really save you anything over Option 2; it's the same code with worse availability.

  Effort: Small (subset of Option 2). But not recommended.

  ---
  Option 5 — Anycast / BGP

  The change: Each node advertises the same public IP via BGP. The internet's routing fabric picks
  the nearest node.

  Why it doesn't help your problem: Anycast picks a node by network proximity, not by which sandbox
  lives where. You'd still have the wrong-node problem 1/N of the time, plus you'd need to run BGP.
  Skip.
  /v1/cluster/members + placement map and pushes config to Envoy via xDS (or rewrites HAProxy config and reloads).

  What happens at request time:
  Browser: https://abc123.sandbox.example.com
              │
              ▼  DNS → Envoy
              ▼
  Envoy reads SNI = abc123.sandbox.example.com
              │
              ▼  Looks up: abc123 → node-C
              ▼  TCP pass-through to node-C
              ▼

  Costs:
  - You're now operating Envoy or HAProxy. This is real ops surface: config push, health checks, version upgrades, observability.
  - Single point of failure in front of the cluster (mitigate with multiple Envoys + L4 LB in front of those, but now you have two ingress tiers).
  - The control-plane process is your code, must be HA, must reconcile correctly.
  - Operator burden: this is no longer "run install.sh on 3 boxes." Now operators must deploy and run Envoy too.

  Effort: Large. Best fit for a managed service offering (you run the cluster), poor fit for self-hosted.

  ---
  Option 4 — Single ingress node

  The change: Designate one node as "ingress only." It runs sandboxd with Caddy but never owns sandboxes. Its Caddy holds a route to every sandbox's owner (basically Option 2, but only on
  this one node). All public DNS points at this node.

  What happens at request time: Same as Option 2, but only one node knows the routes.

  Solves: Same as Option 2.

  Costs:
  - The ingress node is a SPOF. If it dies, all data-plane traffic fails (API still works because clients can hit other nodes directly… if they know the IPs, which they don't because DNS
  control-plane process polls sandboxd's /v1/cluster/members + placement map and pushes config to Envoy via xDS (or rewrites HAProxy
  config and reloads).

  What happens at request time:
  Browser: https://abc123.sandbox.example.com
              │
              ▼  DNS → Envoy
              ▼
  Envoy reads SNI = abc123.sandbox.example.com
              │
              ▼  Looks up: abc123 → node-C
              ▼  TCP pass-through to node-C
              ▼
  node-C's Caddy: local route ✓ → container ✓

  Solves: Same as Option 2, plus the routing decision is centralized so you don't have N copies of the placement map driving N Caddys.

  Costs:
  - You're now operating Envoy or HAProxy. This is real ops surface: config push, health checks, version upgrades, observability.
  - Single point of failure in front of the cluster (mitigate with multiple Envoys + L4 LB in front of those, but now you have two ingress
   tiers).
  - The control-plane process is your code, must be HA, must reconcile correctly.
  - Operator burden: this is no longer "run install.sh on 3 boxes." Now operators must deploy and run Envoy too.

  Effort: Large. Best fit for a managed service offering (you run the cluster), poor fit for self-hosted.

  ---
  Option 4 — Single ingress node

  The change: Designate one node as "ingress only." It runs sandboxd with Caddy but never owns sandboxes. Its Caddy holds a route to every
   sandbox's owner (basically Option 2, but only on this one node). All public DNS points at this node.

  What happens at request time: Same as Option 2, but only one node knows the routes.

  Solves: Same as Option 2.

  Costs:
  - The ingress node is a SPOF. If it dies, all data-plane traffic fails (API still works because clients can hit other nodes directly… if
   they know the IPs, which they don't because DNS points here).

  What happens at request time: Same as Option 2, but only one node knows the routes.

  Solves: Same as Option 2.

  Solves: Same as Option 2.

  Costs:
  - The ingress node is a SPOF. If it dies, all data-plane traffic fails (API still works because clients can hit other nodes directly… if they know the IPs, which they don't because DNS
  points here).
  - All east-west traffic funnels through one node — bandwidth bottleneck and a tempting DDoS target.
  - Doesn't really save you anything over Option 2; it's the same code with worse availability.

  Effort: Small (subset of Option 2). But not recommended.

  ---
  Option 5 — Anycast / BGP

  The change: Each node advertises the same public IP via BGP. The internet's routing fabric picks the nearest node.

  Why it doesn't help your problem: Anycast picks a node by network proximity, not by which sandbox lives where. You'd still have the wrong-node problem 1/N of the time, plus you'd need
  to run BGP. Skip.

  ---
  Part 4: How each option answers your concrete questions

  Question: SDK call writes to right sandbox?
  Today: ✓ always
  Opt 1 (per-sandbox DNS): ✓ always
  Opt 2 (cross-node Caddy): ✓ always
  Opt 3 (Envoy): ✓ always
  ────────────────────────────────────────
  Question: HTTP <id>.sandbox.example.com works?
  Today: 1/N hit rate
  Opt 1 (per-sandbox DNS): ✓ always (after TTL)
  Opt 2 (cross-node Caddy): ✓ always
  Opt 3 (Envoy): ✓ always
  ────────────────────────────────────────
  Question: TLS <id>-<port>.sandbox.example.com works?
  Today: 1/N hit rate
  Opt 1 (per-sandbox DNS): ✓ always (after TTL)
  Opt 2 (cross-node Caddy): ✓ always
  Opt 3 (Envoy): ✓ always
  ────────────────────────────────────────
  Question: TCP node-IP:port works?
  Today: ✓ always (URL is owner-specific)
  Opt 1 (per-sandbox DNS): ✓ unchanged
  Opt 2 (cross-node Caddy): ✓ unchanged
  Opt 3 (Envoy): ✓ unchanged
  ────────────────────────────────────────
  Question: Failover downtime?
  Today: sandbox restarts; URL valid once owner reconciled
  Opt 1 (per-sandbox DNS): + DNS TTL (30-60s)
  Opt 2 (cross-node Caddy): seconds (next placement event)
  Opt 3 (Envoy): seconds (next xDS push)
  ────────────────────────────────────────
  Question: Operator complexity added?
  Today: none
  Opt 1 (per-sandbox DNS): needs DNS API token
  Opt 2 (cross-node Caddy): none beyond cluster setup
  Opt 3 (Envoy): run Envoy + control plane

  My recommendation stays Option 2. It's the cheapest path that makes your cluster behave the way operators expect: "I gave you N nodes, route everything." It doesn't add operator burden
  (no DNS provider, no Envoy), it reuses code you already have, and it leaves Option 3 available later if you want to peel ingress out as a separate tier for scale.

  Want me to sketch the actual implementation plan for Option 2 — the reconciler, the failure modes, where it hooks into internal/cluster and pkg/caddy?

✻ Churned for 1m 36s

❯ <sandbox-id>.<cluster-ip>sandbox.example.com if I start with this only how will the edge routing happen? What will go inside my Cloudflare and how will the SDK go? Is this a viable     
  solution? Now every node doesn't have to maintain the information of all the sandboxes. It just needs to understand what is the cluster IP, and then we can redirect to the              
  corresponding cluster. how is this architecture and what are the caveat?                                                                                                                 

⏺ This is a good idea. Let me work through it carefully, because it's actually one of the cleanest options on the table — with one specific tradeoff you need to be OK with.

  The scheme

  Instead of <id>.sandbox.example.com (one logical hostname for every sandbox), the URL becomes:

  <sandbox-id>.<node-name>.sandbox.example.com

  The owner node's identity is baked into the hostname. The URL itself is a routing instruction.

  So if sandbox abc123 lives on node-c, its public URL is:

  https://abc123.node-c.sandbox.example.com

  Cloudflare config

  This is the elegant part. You need exactly N+1 records, total, regardless of how many sandboxes you create:

  ┌───────┬──────────────────┬───────────────────────┬───────────────────────────────┐
  │ Type  │       Name       │         Value         │            Purpose            │
  ├───────┼──────────────────┼───────────────────────┼───────────────────────────────┤
  │ CNAME │ sandbox          │ <NLB-DNS or any node> │ API plane (round-robins fine) │
  ├───────┼──────────────────┼───────────────────────┼───────────────────────────────┤
  │ A     │ *.node-a.sandbox │ node-A-public-IP      │ All sandboxes on node-A       │
  ├───────┼──────────────────┼───────────────────────┼───────────────────────────────┤
  │ A     │ *.node-b.sandbox │ node-B-public-IP      │ All sandboxes on node-B       │
  ├───────┼──────────────────┼───────────────────────┼───────────────────────────────┤
  │ A     │ *.node-c.sandbox │ node-C-public-IP      │ All sandboxes on node-C       │
  └───────┴──────────────────┴───────────────────────┴───────────────────────────────┘

  Add a 4th node? Add one record: *.node-d.sandbox → node-D-IP. That's a one-time operator step on cluster expansion, not per-sandbox. No DNS API integration in sandboxd, no rate limits
  to worry about, no provider lock-in.

  What happens at request time

  Browser opens https://abc123.node-c.sandbox.example.com
              │
              ▼  DNS query for abc123.node-c.sandbox.example.com
              ▼  Cloudflare matches *.node-c.sandbox.example.com → node-C-IP
              ▼
  TCP connection lands DIRECTLY on node-C (no LB, no other node hops)
              │
              ▼
  node-C's Caddy: "host = abc123.node-c.sandbox.example.com → local container abc123" ✓
              │
              ▼
  200 OK

  No cross-node forwarding. No placement map lookup at the edge. DNS itself is the placement-aware router, and DNS already scales to billions of records globally.

  How the SDK works

  API calls are unchanged. SDK still talks to https://sandbox.example.com. Round-robin DNS / NLB on that hostname works fine because clusterForwardWrap (pkg/api/v1/cluster_handler.go:30)
  handles cross-node forwarding for the API plane. So:

  const sb = new Sandbox({ baseURL: "https://sandbox.example.com" });
  const sandbox = await sb.create({ image: "node:20" });

  // What changes is what the API returns:
  console.log(sandbox.publicURL);
  // Today:    https://abc123.sandbox.example.com
  // Proposal: https://abc123.node-c.sandbox.example.com

  When the user opens an HTTP port:

  const port = await sandbox.exposePort(8080, "http");
  console.log(port.url);
  // https://abc123-8080.node-c.sandbox.example.com

  The owner node's name is just appended into the hostname sandboxd returns. No DNS writes, no Cloudflare API calls, no Caddy reconciler — just string composition in pkg/caddy/client.go's
   URL builder.

  TLS certs

  Each node already does its own DNS-01 cert issuance via install.sh. Today it issues a wildcard for *.sandbox.example.com. Switch to *.node-c.sandbox.example.com on node-C,
  *.node-a.sandbox.example.com on node-A, etc. Each node solves DNS-01 only for its own wildcard. Lower contention, no shared cert storage, no risk of two nodes racing to write the same
  _acme-challenge TXT record.

  This is actually cleaner than today's setup, where all 3 nodes try to issue and renew the same *.sandbox.example.com cert independently against Let's Encrypt's rate limits.

  What still works the same

  ┌────────────────────────────────────┬───────────────────────────────────────────────────┐
  │              Question              │                      Answer                       │
  ├────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ SDK writes a file → right sandbox? │ ✓ always (API plane forwarding, unchanged)        │
  ├────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ Open HTTP port → reachable?        │ ✓ always (DNS resolves to owner directly)         │
  ├────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ Open TLS port → reachable?         │ ✓ always (same hostname matches *.node-c... cert) │
  ├────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ Open TCP port → reachable?         │ ✓ always (already direct-to-IP)                   │
  ├────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ Add a node?                        │ One Cloudflare record                             │
  ├────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ Per-sandbox DNS writes?            │ None                                              │
  ├────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ Cross-node Caddy reconciler?       │ None                                              │
  ├────────────────────────────────────┼───────────────────────────────────────────────────┤
  │ Operator burden vs today?          │ One extra DNS record per node added               │
  └────────────────────────────────────┴───────────────────────────────────────────────────┘

  The caveat that matters: URL changes on failover

  This is the one trade. When node-c dies and the dead-owner reconciler reassigns abc123 to node-a:

  Before failover:  https://abc123.node-c.sandbox.example.com
  After failover:   https://abc123.node-a.sandbox.example.com

  The hostname literally changes. Anything that cached the old URL — a browser tab, a webhook recipient, a copy-pasted link in Slack, a QR code printed on a sticker — now points at the
  wrong node. node-C is dead so the connection times out; even if node-C came back, it doesn't own the sandbox anymore so its Caddy returns 404.

  Concretely this hurts in scenarios like:

  1. Long-lived browser tabs. User opens the sandbox URL, leaves the tab open overnight, sandbox fails over while they're asleep, refresh fails. They must re-fetch via the SDK.
  2. Shared/public links. Someone publishes the URL on Twitter or in docs. Failover breaks the link permanently — no DNS update will fix it without re-issuing the URL to the audience.
  3. Webhooks / external callbacks. A third-party service registered abc123.node-c.sandbox.example.com as a webhook target. After failover, the third party gets connection refused until
  you re-register.
  4. Cookies / origin-bound state. Cookies set on abc123.node-c.sandbox.example.com don't carry to abc123.node-a.sandbox.example.com — they're different origins to the browser.

  The mitigation in all four cases is the same: the SDK / your dashboard must re-fetch the URL from the API after a failover event. That's already true for some things (TCP host:port URLs
   change today), so it's not a new pattern, but it becomes the dominant pattern.

  By contrast, in Options 1 and 2 the URL abc123.sandbox.example.com stays stable across failover. That's the one property you give up here.

  Two smaller caveats

  5. URL leaks node identity. abc123.node-c.sandbox.example.com tells the world that this sandbox is on node-C. An attacker can target node-C specifically (DDoS, fingerprint your
  topology, count your nodes). Mitigation: use opaque node aliases — n1, n2, n3 instead of node-a, node-b, node-c — so the URL doesn't disclose your operational naming. The IP it resolves
   to is still discoverable, but at least the hostname doesn't volunteer it.

  6. Cluster IP is public. Each node's IP is the answer to its wildcard DNS query, so each node's IP must be publicly routable on :443. You can't hide nodes behind a load balancer with
  this scheme — the LB removes the per-node addressability that makes this work. (You could front each node with its own per-node LB if you want failure isolation in front of a single
  node, but you can't share one LB across all nodes.)

  So is it viable

  Yes — and arguably it's the best fit for self-hosted. Here's how it stacks up:

  ┌────────────────────────────────────┬──────────────────────┬───────────────────────────┬─────────────────────────────────────┬──────────────────────────┐
  │                                    │        Today         │  Opt 1 (per-sandbox DNS)  │      Opt 2 (cross-node Caddy)       │       Opt 6 (this)       │
  ├────────────────────────────────────┼──────────────────────┼───────────────────────────┼─────────────────────────────────────┼──────────────────────────┤
  │ HTTP/TLS URL works                 │ 1/N                  │ ✓                         │ ✓                                   │ ✓                        │
  ├────────────────────────────────────┼──────────────────────┼───────────────────────────┼─────────────────────────────────────┼──────────────────────────┤
  │ URL stable across failover         │ ✓                    │ ✓                         │ ✓                                   │ ✗                        │
  ├────────────────────────────────────┼──────────────────────┼───────────────────────────┼─────────────────────────────────────┼──────────────────────────┤
  │ Per-sandbox DNS writes             │ none                 │ yes (rate-limited)        │ none                                │ none                     │
  ├────────────────────────────────────┼──────────────────────┼───────────────────────────┼─────────────────────────────────────┼──────────────────────────┤
  │ Per-sandbox Caddy state            │ none                 │ none                      │ yes (total_sandboxes × N)           │ none                     │
  ├────────────────────────────────────┼──────────────────────┼───────────────────────────┼─────────────────────────────────────┼──────────────────────────┤
  │ Code to write                      │ none                 │ DNS provider drivers      │ reconciler + Caddy stub-route logic │ URL composition only     │
  ├────────────────────────────────────┼──────────────────────┼───────────────────────────┼─────────────────────────────────────┼──────────────────────────┤
  │ Operator setup                     │ 2 DNS records        │ 2 records + DNS API token │ 2 records                           │ N+1 records              │
  ├────────────────────────────────────┼──────────────────────┼───────────────────────────┼─────────────────────────────────────┼──────────────────────────┤
  │ Operator burden when adding a node │ none                 │ none                      │ none                                │ one DNS record           │
  ├────────────────────────────────────┼──────────────────────┼───────────────────────────┼─────────────────────────────────────┼──────────────────────────┤
  │ Failure mode on failover           │ 502 until reconciled │ DNS TTL gap               │ seconds                             │ URL stale, must re-fetch │
  └────────────────────────────────────┴──────────────────────┴───────────────────────────┴─────────────────────────────────────┴──────────────────────────┘

  The shape: you're moving the routing intelligence out of the cluster and into DNS, by encoding it in the URL. That's the same trick CDNs use (<thing>.<region>.fastly.net). It scales
  infinitely and costs nothing because DNS is doing all the work.

  The reason I didn't propose it earlier is that I assumed URL stability across failover was a hard requirement for your product. If you're OK with "the SDK gives you a fresh URL after 
  failover, don't cache it long-term," this is the simplest correct answer. Option 2 (cross-node Caddy) is what you'd build only if URL stability is non-negotiable.

  Possible hybrid

  If you want the best of both later: ship Opt 6 now (URL bakes in owner), and additionally maintain <id>.sandbox.example.com as a stable fallback via Opt 2 reconciler. New code uses
  <id>.<node>.sandbox.example.com for fast direct routing; old cached URLs hit the stable hostname and get cross-node-proxied. But you don't need this on day 1.

  My recommendation: ship Opt 6. It's the smallest diff, zero ongoing operator cost, no rate limits, and the failover-URL-changes property is a documentable contract the SDK can
  transparently handle (re-fetch on 502/timeout).

  Want me to sketch the actual code change — where the URL is composed in pkg/caddy/client.go and what the install/cluster scripts need to do for the per-node wildcard cert?
