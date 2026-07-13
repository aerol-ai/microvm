package containerd

// containerIPv4FromTaskFn resolves the task's primary IPv4. Tests stub this on
// non-linux hosts where netlink/netns probing is unavailable.
var containerIPv4FromTaskFn = containerIPv4FromTask
