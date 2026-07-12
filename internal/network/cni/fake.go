package cni

import (
	"context"
	"fmt"
	"sync"
)

// FakeRunner is an in-memory CNI backend for unit tests.
type FakeRunner struct {
	mu     sync.Mutex
	adds   []call
	dels   []call
	ips    map[string]string // containerID -> ip
	addErr error
	delErr error
}

type call struct {
	Netns, ContainerID string
}

func NewFakeRunner() *FakeRunner {
	return &FakeRunner{ips: make(map[string]string)}
}

func (f *FakeRunner) SetAddError(err error) { f.addErr = err }
func (f *FakeRunner) SetDelError(err error) { f.delErr = err }

func (f *FakeRunner) Add(ctx context.Context, netnsPath, containerID string) (Result, error) {
	_ = ctx
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return Result{}, f.addErr
	}
	f.adds = append(f.adds, call{netnsPath, containerID})
	if ip, ok := f.ips[containerID]; ok {
		return Result{IP4: ip}, nil
	}
	ip := fmt.Sprintf("10.88.%d.%d", len(f.adds)/254+1, len(f.adds)%254+1)
	f.ips[containerID] = ip
	return Result{IP4: ip}, nil
}

func (f *FakeRunner) Del(ctx context.Context, netnsPath, containerID string) error {
	_ = ctx
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delErr != nil {
		return f.delErr
	}
	f.dels = append(f.dels, call{netnsPath, containerID})
	delete(f.ips, containerID)
	return nil
}

func (f *FakeRunner) Adds() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]call(nil), f.adds...)
	return out
}

func (f *FakeRunner) Dels() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]call(nil), f.dels...)
	return out
}
