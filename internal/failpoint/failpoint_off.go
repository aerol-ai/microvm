//go:build !itest_failpoints

package failpoint

// Hit does nothing outside itest builds. It must stay an empty body: the
// compiler inlines it to nothing, which is what keeps the create path free of
// a file read in every release build.
func Hit(name, key string) {}
