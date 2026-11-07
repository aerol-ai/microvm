//go:build !linux && !darwin

package main

func renameNoReplace(src, dst string) error {
	return renameNoReplaceFallback(src, dst)
}
