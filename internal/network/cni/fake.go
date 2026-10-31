package cni

import (
	"context"
	"fmt"
	"sync"
)

// FakeRunner is an in-memory CNI backend for unit tests.
type FakeRunner struct {
	mu      sync.Mutex
	adds    []call
	dels    []call
	masq    []MasqCall
	ips     map[string]string // containerID -> ip
	addErr  error
	delErr  error
	masqErr error
}

// MasqCall records one TeardownIPMasq call.
type MasqCall struct {
	ContainerID, ContainerIP string
}

type call struct {
	Netns, ContainerID string
}

func NewFakeRunner() *FakeRunner {
	return &FakeRunner{ips: make(map[string]string)}
}

func (f *FakeRunner) SetAddError(err error) { f.addErr = err }
func (f *FakeRunner) SetDelError(err error) { f.delErr = err }

// SetMasqError makes TeardownIPMasq fail with err (nil clears it).
func (f *FakeRunner) SetMasqError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.masqErr = err
}

// TeardownIPMasq records the call; it implements IPMasqTeardown.
func (f *FakeRunner) TeardownIPMasq(ctx context.Context, containerID, containerIP string) error {
	_ = ctx
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.masqErr != nil {
		return f.masqErr
	}
	f.masq = append(f.masq, MasqCall{ContainerID: containerID, ContainerIP: containerIP})
	return nil
}

// MasqTeardowns returns the recorded TeardownIPMasq calls.
func (f *FakeRunner) MasqTeardowns() []MasqCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]MasqCall(nil), f.masq...)
}

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
