// Package images holds AerolVM's ready-made sandbox images, one folder per
// image with a Dockerfile in it. Nothing is pushed to a registry: the docs
// build each one on the reader's own server with the SDKs' image builder,
// which sends only the Dockerfile. The test here keeps every Dockerfile
// buildable that way.
package images
