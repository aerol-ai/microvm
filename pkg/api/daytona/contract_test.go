package daytona

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	apiclient "github.com/daytonaio/daytona/libs/api-client-go"
	sdktypes "github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

type contractCase struct {
	name string
	run  func(t *testing.T, env *daytonaContractEnv)
}

func TestDaytonaGeneratedSandboxContracts(t *testing.T) {
	cases := []contractCase{
		{
			name: "create_from_buildinfo",
			run: func(t *testing.T, env *daytonaContractEnv) {
				req := newGeneratedCreateRequest("alpine:3.20")
				resp, httpResp, err := env.api.SandboxAPI.CreateSandbox(env.ctx).
					CreateSandbox(*req).
					XDaytonaOrganizationID(contractOrgID).
					Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, resp.GetId())
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", resp.GetId(), err)
				}
				if stored.Image != "alpine:3.20" {
					t.Fatalf("stored.Image = %q, want %q", stored.Image, "alpine:3.20")
				}
				if resp.GetState() != apiclient.SANDBOXSTATE_STARTED {
					t.Fatalf("resp.State = %q, want %q", resp.GetState(), apiclient.SANDBOXSTATE_STARTED)
				}
			},
		},
		{
			name: "create_with_name_and_user",
			run: func(t *testing.T, env *daytonaContractEnv) {
				req := newGeneratedCreateRequest("ubuntu:22.04")
				req.SetName("named-generated")
				req.SetUser("coder")
				resp, httpResp, err := env.api.SandboxAPI.CreateSandbox(env.ctx).
					CreateSandbox(*req).
					Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				meta, err := env.loadDaytonaMeta(resp.GetId())
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", resp.GetId(), err)
				}
				if resp.GetName() != "named-generated" {
					t.Fatalf("resp.Name = %q, want %q", resp.GetName(), "named-generated")
				}
				if resp.GetUser() != "coder" {
					t.Fatalf("resp.User = %q, want %q", resp.GetUser(), "coder")
				}
				if meta.Name != "named-generated" || meta.User != "coder" {
					t.Fatalf("stored metadata = %+v", meta)
				}
			},
		},
		{
			name: "create_rejects_name_matching_existing_sandbox_id",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSandbox(contractSandboxSeed{ID: "sb-shadow-owner", Name: "unrelated-shadow-owner"})

				req := newGeneratedCreateRequest("ubuntu:22.04")
				req.SetName("sb-shadow-owner")
				_, httpResp, err := env.api.SandboxAPI.CreateSandbox(env.ctx).
					CreateSandbox(*req).
					Execute()

				assertGeneratedAPIErrorStatus(t, httpResp, err, http.StatusConflict)
			},
		},
		{
			name: "create_with_labels_and_target",
			run: func(t *testing.T, env *daytonaContractEnv) {
				req := newGeneratedCreateRequest("python:3.12")
				req.SetName("labels-and-target")
				req.SetLabels(map[string]string{"team": "api", "tier": "control"})
				req.SetTarget("us-east-1")
				resp, httpResp, err := env.api.SandboxAPI.CreateSandbox(env.ctx).
					CreateSandbox(*req).
					Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				meta, err := env.loadDaytonaMeta(resp.GetId())
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", resp.GetId(), err)
				}
				if resp.GetTarget() != "us-east-1" {
					t.Fatalf("resp.Target = %q, want %q", resp.GetTarget(), "us-east-1")
				}
				if got := resp.GetLabels()["team"]; got != "api" {
					t.Fatalf("resp.Labels[team] = %q, want %q", got, "api")
				}
				if meta.Target != "us-east-1" || meta.Labels["tier"] != "control" {
					t.Fatalf("stored metadata = %+v", meta)
				}
			},
		},
		{
			name: "create_with_snapshot_field",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSnapshot(contractSnapshotSeed{Name: "base-snapshot", Image: "snapshots/base:v1", ImageID: "sha256:base-snapshot", SourceSandboxID: "seed-source"})

				req := apiclient.NewCreateSandbox()
				req.SetName("from-snapshot")
				req.SetSnapshot("base-snapshot")
				resp, httpResp, err := env.api.SandboxAPI.CreateSandbox(env.ctx).
					CreateSandbox(*req).
					Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, resp.GetId())
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", resp.GetId(), err)
				}
				meta, err := env.loadDaytonaMeta(resp.GetId())
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", resp.GetId(), err)
				}
				// Daytona's snapshot field is a snapshot *name*, not an image ref.
				// The facade looks the name up in the snapshot store and uses the
				// row's Image as the runtime image; the snapshot name itself is
				// preserved in the per-sandbox compat metadata for read-back.
				if stored.Image != "snapshots/base:v1" {
					t.Fatalf("stored.Image = %q, want %q (resolved from snapshot row)", stored.Image, "snapshots/base:v1")
				}
				if valueOrEmpty(meta.Snapshot) != "base-snapshot" {
					t.Fatalf("stored snapshot metadata = %q, want %q", valueOrEmpty(meta.Snapshot), "base-snapshot")
				}
				if resp.GetSnapshot() != "base-snapshot" {
					t.Fatalf("resp.Snapshot = %q, want %q", resp.GetSnapshot(), "base-snapshot")
				}
			},
		},
		{
			name: "create_with_intervals",
			run: func(t *testing.T, env *daytonaContractEnv) {
				req := newGeneratedCreateRequest("golang:1.24")
				req.SetAutoStopInterval(5)
				req.SetAutoDeleteInterval(15)
				req.SetAutoArchiveInterval(30)
				resp, httpResp, err := env.api.SandboxAPI.CreateSandbox(env.ctx).
					CreateSandbox(*req).
					Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, resp.GetId())
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", resp.GetId(), err)
				}
				meta, err := env.loadDaytonaMeta(resp.GetId())
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", resp.GetId(), err)
				}
				if stored.Lifecycle.StopIfIdleFor != 5*time.Minute {
					t.Fatalf("stored.StopIfIdleFor = %v, want %v", stored.Lifecycle.StopIfIdleFor, 5*time.Minute)
				}
				if stored.Lifecycle.DestroyIfIdleFor != 15*time.Minute {
					t.Fatalf("stored.DestroyIfIdleFor = %v, want %v", stored.Lifecycle.DestroyIfIdleFor, 15*time.Minute)
				}
				if meta.AutoArchiveInterval == nil || *meta.AutoArchiveInterval != 30 {
					t.Fatalf("stored.AutoArchiveIntervalMinutes = %+v, want 30", meta.AutoArchiveInterval)
				}
				if resp.AutoStopInterval == nil || *resp.AutoStopInterval != 5 {
					t.Fatalf("resp.AutoStopInterval = %+v, want 5", resp.AutoStopInterval)
				}
				if resp.AutoDeleteInterval == nil || *resp.AutoDeleteInterval != 15 {
					t.Fatalf("resp.AutoDeleteInterval = %+v, want 15", resp.AutoDeleteInterval)
				}
				if resp.AutoArchiveInterval == nil || *resp.AutoArchiveInterval != 30 {
					t.Fatalf("resp.AutoArchiveInterval = %+v, want 30", resp.AutoArchiveInterval)
				}
			},
		},
		{
			name: "create_with_network_block_all",
			run: func(t *testing.T, env *daytonaContractEnv) {
				req := newGeneratedCreateRequest("node:22")
				req.SetNetworkBlockAll(true)
				resp, httpResp, err := env.api.SandboxAPI.CreateSandbox(env.ctx).
					CreateSandbox(*req).
					Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, resp.GetId())
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", resp.GetId(), err)
				}
				if !stored.NetworkBlockAll || !resp.GetNetworkBlockAll() {
					t.Fatalf("networkBlockAll not preserved: stored=%v resp=%v", stored.NetworkBlockAll, resp.GetNetworkBlockAll())
				}
			},
		},
		{
			name: "create_with_env",
			run: func(t *testing.T, env *daytonaContractEnv) {
				req := newGeneratedCreateRequest("ruby:3.4")
				req.SetEnv(map[string]string{"LANG": "en_US.UTF-8", "APP_ENV": "contract"})
				resp, httpResp, err := env.api.SandboxAPI.CreateSandbox(env.ctx).
					CreateSandbox(*req).
					Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, resp.GetId())
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", resp.GetId(), err)
				}
				if stored.Env["APP_ENV"] != "contract" {
					t.Fatalf("stored.Env = %+v", stored.Env)
				}
				if resp.GetEnv()["LANG"] != "en_US.UTF-8" {
					t.Fatalf("resp.Env = %+v", resp.GetEnv())
				}
			},
		},
		{
			name: "list_unpaginated_returns_all",
			run: func(t *testing.T, env *daytonaContractEnv) {
				now := time.Now().UTC().Round(time.Second)
				older := env.seedSandbox(contractSandboxSeed{ID: "sb-older", Name: "older", CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour), LastActiveAt: now.Add(-time.Hour)})
				newer := env.seedSandbox(contractSandboxSeed{ID: "sb-newer", Name: "newer", CreatedAt: now, UpdatedAt: now, LastActiveAt: now})

				resp, httpResp, err := env.api.SandboxAPI.ListSandboxes(env.ctx).Execute()
				if err != nil {
					t.Fatalf("ListSandboxes() error = %v", err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("ListSandboxes() status = %+v", httpResp)
				}
				if len(resp) != 2 {
					t.Fatalf("len(resp) = %d, want 2", len(resp))
				}
				if resp[0].GetId() != newer.ID || resp[1].GetId() != older.ID {
					t.Fatalf("unexpected order: first=%q second=%q", resp[0].GetId(), resp[1].GetId())
				}
			},
		},
		{
			name: "list_paginated_defaults",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSandbox(contractSandboxSeed{ID: "sb-one", Name: "one"})
				env.seedSandbox(contractSandboxSeed{ID: "sb-two", Name: "two", CreatedAt: time.Now().UTC().Add(time.Minute), UpdatedAt: time.Now().UTC().Add(time.Minute), LastActiveAt: time.Now().UTC().Add(time.Minute)})

				resp, httpResp, err := env.api.SandboxAPI.ListSandboxesPaginated(env.ctx).Execute()
				if err != nil {
					t.Fatalf("ListSandboxesPaginated() error = %v", err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("ListSandboxesPaginated() status = %+v", httpResp)
				}
				if resp.GetPage() != 1 || resp.GetTotal() != 2 || len(resp.GetItems()) != 2 {
					t.Fatalf("unexpected pagination: page=%v total=%v len=%d", resp.GetPage(), resp.GetTotal(), len(resp.GetItems()))
				}
			},
		},
		{
			name: "list_paginated_by_name",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSandbox(contractSandboxSeed{Name: "alpha-one"})
				env.seedSandbox(contractSandboxSeed{Name: "beta-two"})

				resp, httpResp, err := env.api.SandboxAPI.ListSandboxesPaginated(env.ctx).
					Name("alpha").
					Execute()
				if err != nil {
					t.Fatalf("ListSandboxesPaginated(Name) error = %v", err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("ListSandboxesPaginated(Name) status = %+v", httpResp)
				}
				if len(resp.GetItems()) != 1 || resp.GetItems()[0].GetName() != "alpha-one" {
					t.Fatalf("unexpected filtered items: %+v", resp.GetItems())
				}
			},
		},
		{
			name: "list_paginated_by_labels",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSandbox(contractSandboxSeed{Name: "api-sandbox", Labels: map[string]string{"team": "api"}})
				env.seedSandbox(contractSandboxSeed{Name: "web-sandbox", Labels: map[string]string{"team": "web"}})

				resp, httpResp, err := env.api.SandboxAPI.ListSandboxesPaginated(env.ctx).
					Labels(labelJSON(map[string]string{"team": "api"})).
					Execute()
				if err != nil {
					t.Fatalf("ListSandboxesPaginated(Labels) error = %v", err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("ListSandboxesPaginated(Labels) status = %+v", httpResp)
				}
				if len(resp.GetItems()) != 1 || resp.GetItems()[0].GetName() != "api-sandbox" {
					t.Fatalf("unexpected filtered items: %+v", resp.GetItems())
				}
			},
		},
		{
			name: "get_by_id",
			run: func(t *testing.T, env *daytonaContractEnv) {
				const sandboxName = "sandbox-by-id"
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-get-id", Name: sandboxName})

				resp, httpResp, err := env.api.SandboxAPI.GetSandbox(env.ctx, seed.ID).Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)
				if resp.GetId() != seed.ID || resp.GetName() != sandboxName {
					t.Fatalf("unexpected sandbox payload: id=%q name=%q", resp.GetId(), resp.GetName())
				}
			},
		},
		{
			name: "get_by_name",
			run: func(t *testing.T, env *daytonaContractEnv) {
				const sandboxName = "sandbox-by-name"
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-get-name", Name: sandboxName})

				resp, httpResp, err := env.api.SandboxAPI.GetSandbox(env.ctx, sandboxName).Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)
				if resp.GetId() != seed.ID || resp.GetName() != sandboxName {
					t.Fatalf("unexpected sandbox payload: id=%q name=%q", resp.GetId(), resp.GetName())
				}
			},
		},
		{
			name: "start_by_id",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-start-id", Name: "start-id", Status: models.SandboxStatusStopped})

				resp, httpResp, err := env.api.SandboxAPI.StartSandbox(env.ctx, seed.ID).Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", seed.ID, err)
				}
				if stored.Status != models.SandboxStatusStarted || resp.GetState() != apiclient.SANDBOXSTATE_STARTED {
					t.Fatalf("unexpected started status: stored=%q resp=%q", stored.Status, resp.GetState())
				}
			},
		},
		{
			name: "start_by_name",
			run: func(t *testing.T, env *daytonaContractEnv) {
				const sandboxName = "start-name"
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-start-name", Name: sandboxName, Status: models.SandboxStatusStopped})

				resp, httpResp, err := env.api.SandboxAPI.StartSandbox(env.ctx, sandboxName).Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", seed.ID, err)
				}
				if stored.Status != models.SandboxStatusStarted || resp.GetState() != apiclient.SANDBOXSTATE_STARTED {
					t.Fatalf("unexpected started status: stored=%q resp=%q", stored.Status, resp.GetState())
				}
			},
		},
		{
			name: "stop_by_id",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-stop-id", Name: "stop-id", Status: models.SandboxStatusStarted})

				resp, httpResp, err := env.api.SandboxAPI.StopSandbox(env.ctx, seed.ID).Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", seed.ID, err)
				}
				if stored.Status != models.SandboxStatusStopped || resp.GetState() != apiclient.SANDBOXSTATE_STOPPED {
					t.Fatalf("unexpected stopped status: stored=%q resp=%q", stored.Status, resp.GetState())
				}
			},
		},
		{
			name: "stop_by_name",
			run: func(t *testing.T, env *daytonaContractEnv) {
				const sandboxName = "stop-name"
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-stop-name", Name: sandboxName, Status: models.SandboxStatusStarted})

				resp, httpResp, err := env.api.SandboxAPI.StopSandbox(env.ctx, sandboxName).Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", seed.ID, err)
				}
				if stored.Status != models.SandboxStatusStopped || resp.GetState() != apiclient.SANDBOXSTATE_STOPPED {
					t.Fatalf("unexpected stopped status: stored=%q resp=%q", stored.Status, resp.GetState())
				}
			},
		},
		{
			name: "replace_labels_by_id",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-label-id", Name: "label-id", Labels: map[string]string{"old": "value"}})

				resp, httpResp, err := env.api.SandboxAPI.ReplaceLabels(env.ctx, seed.ID).
					SandboxLabels(apiclient.SandboxLabels{Labels: map[string]string{"team": "backend"}}).
					Execute()
				if err != nil {
					t.Fatalf("ReplaceLabels(%s) error = %v", seed.ID, err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("ReplaceLabels(%s) status = %+v", seed.ID, httpResp)
				}
				meta, err := env.loadDaytonaMeta(seed.ID)
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", seed.ID, err)
				}
				if resp.GetLabels()["team"] != "backend" || meta.Labels["team"] != "backend" {
					t.Fatalf("labels not updated: resp=%+v meta=%+v", resp.GetLabels(), meta.Labels)
				}
			},
		},
		{
			name: "replace_labels_by_name",
			run: func(t *testing.T, env *daytonaContractEnv) {
				const sandboxName = "label-name"
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-label-name", Name: sandboxName})

				resp, httpResp, err := env.api.SandboxAPI.ReplaceLabels(env.ctx, sandboxName).
					SandboxLabels(apiclient.SandboxLabels{Labels: map[string]string{"component": "gateway"}}).
					Execute()
				if err != nil {
					t.Fatalf("ReplaceLabels(%s) error = %v", sandboxName, err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("ReplaceLabels(%s) status = %+v", sandboxName, httpResp)
				}
				meta, err := env.loadDaytonaMeta(seed.ID)
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", seed.ID, err)
				}
				if resp.GetLabels()["component"] != "gateway" || meta.Labels["component"] != "gateway" {
					t.Fatalf("labels not updated: resp=%+v meta=%+v", resp.GetLabels(), meta.Labels)
				}
			},
		},
		{
			name: "set_autostop_interval",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-autostop", Name: "auto-stop"})

				resp, httpResp, err := env.api.SandboxAPI.SetAutostopInterval(env.ctx, seed.ID, 12).Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", seed.ID, err)
				}
				meta, err := env.loadDaytonaMeta(seed.ID)
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", seed.ID, err)
				}
				if stored.Lifecycle.StopIfIdleFor != 12*time.Minute {
					t.Fatalf("stored.StopIfIdleFor = %v, want %v", stored.Lifecycle.StopIfIdleFor, 12*time.Minute)
				}
				if meta.AutoStopInterval == nil || *meta.AutoStopInterval != 12 {
					t.Fatalf("stored.AutoStopIntervalMinutes = %+v, want 12", meta.AutoStopInterval)
				}
				if resp.AutoStopInterval == nil || *resp.AutoStopInterval != 12 {
					t.Fatalf("resp.AutoStopInterval = %+v, want 12", resp.AutoStopInterval)
				}
			},
		},
		{
			name: "clear_autostop_interval_with_zero",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{
					ID:               "sb-clear-autostop",
					Name:             "clear-auto-stop",
					AutoStopInterval: ptrFloat32(9),
					Lifecycle:        models.Lifecycle{StopIfIdleFor: 9 * time.Minute},
				})

				resp, httpResp, err := env.api.SandboxAPI.SetAutostopInterval(env.ctx, seed.ID, 0).Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", seed.ID, err)
				}
				meta, err := env.loadDaytonaMeta(seed.ID)
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", seed.ID, err)
				}
				if stored.Lifecycle.StopIfIdleFor != 0 {
					t.Fatalf("stored.StopIfIdleFor = %v, want 0", stored.Lifecycle.StopIfIdleFor)
				}
				if meta.AutoStopInterval != nil || resp.AutoStopInterval != nil {
					t.Fatalf("auto-stop interval not cleared: meta=%+v resp=%+v", meta.AutoStopInterval, resp.AutoStopInterval)
				}
			},
		},
		{
			name: "set_autodelete_interval",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-autodelete", Name: "auto-delete"})

				resp, httpResp, err := env.api.SandboxAPI.SetAutoDeleteInterval(env.ctx, seed.ID, 25).Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", seed.ID, err)
				}
				meta, err := env.loadDaytonaMeta(seed.ID)
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", seed.ID, err)
				}
				if stored.Lifecycle.DestroyIfIdleFor != 25*time.Minute {
					t.Fatalf("stored.DestroyIfIdleFor = %v, want %v", stored.Lifecycle.DestroyIfIdleFor, 25*time.Minute)
				}
				if meta.AutoDeleteInterval == nil || *meta.AutoDeleteInterval != 25 {
					t.Fatalf("stored.AutoDeleteIntervalMinutes = %+v, want 25", meta.AutoDeleteInterval)
				}
				if resp.AutoDeleteInterval == nil || *resp.AutoDeleteInterval != 25 {
					t.Fatalf("resp.AutoDeleteInterval = %+v, want 25", resp.AutoDeleteInterval)
				}
			},
		},
		{
			name: "set_autoarchive_interval",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-autoarchive", Name: "auto-archive"})

				resp, httpResp, err := env.api.SandboxAPI.SetAutoArchiveInterval(env.ctx, seed.ID, 45).Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				meta, err := env.loadDaytonaMeta(seed.ID)
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", seed.ID, err)
				}
				if meta.AutoArchiveInterval == nil || *meta.AutoArchiveInterval != 45 {
					t.Fatalf("stored.AutoArchiveIntervalMinutes = %+v, want 45", meta.AutoArchiveInterval)
				}
				if resp.AutoArchiveInterval == nil || *resp.AutoArchiveInterval != 45 {
					t.Fatalf("resp.AutoArchiveInterval = %+v, want 45", resp.AutoArchiveInterval)
				}
			},
		},
		{
			name: "resize_sandbox",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-resize", Name: "resize-me", CPU: 2, MemoryMB: 2048, DiskGB: 10})

				resizeReq := apiclient.NewResizeSandbox()
				resizeReq.SetCpu(4)
				resizeReq.SetMemory(8)
				resizeReq.SetDisk(40)

				resp, httpResp, err := env.api.SandboxAPI.ResizeSandbox(env.ctx, seed.ID).
					ResizeSandbox(*resizeReq).
					Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				stored, err := env.store.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", seed.ID, err)
				}
				if stored.CPU != 4 || stored.MemoryMB != 8192 || stored.DiskGB != 40 {
					t.Fatalf("unexpected resized sandbox: %+v", stored)
				}
			},
		},
		{
			name: "toolbox_proxy_url",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-toolbox-url", Name: "toolbox-url"})

				resp, httpResp, err := env.api.SandboxAPI.GetToolboxProxyUrl(env.ctx, seed.ID).Execute()
				if err != nil {
					t.Fatalf("GetToolboxProxyUrl(%s) error = %v", seed.ID, err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("GetToolboxProxyUrl(%s) status = %+v", seed.ID, httpResp)
				}
				if resp.GetUrl() != env.server.URL+ToolboxPrefix {
					t.Fatalf("resp.URL = %q, want %q", resp.GetUrl(), env.server.URL+ToolboxPrefix)
				}
			},
		},
		{
			name: "preview_url",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-preview", Name: "preview"})

				resp, httpResp, err := env.api.SandboxAPI.GetPortPreviewUrl(env.ctx, seed.ID, 3000).Execute()
				if err != nil {
					t.Fatalf("GetPortPreviewUrl(%s, 3000) error = %v", seed.ID, err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("GetPortPreviewUrl(%s, 3000) status = %+v", seed.ID, httpResp)
				}
				if resp.GetSandboxId() != seed.ID {
					t.Fatalf("resp.SandboxId = %q, want %q", resp.GetSandboxId(), seed.ID)
				}
				wantURL := fmt.Sprintf("http://%s/%s/proxy/%d/", contractPublicHost, seed.ID, 3000)
				if resp.GetUrl() != wantURL || resp.GetToken() != "" {
					t.Fatalf("unexpected preview payload: url=%q token=%q", resp.GetUrl(), resp.GetToken())
				}
				stored, err := env.store.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", seed.ID, err)
				}
				if len(stored.ExposedPorts) != 1 || stored.ExposedPorts[0].Port != 3000 {
					t.Fatalf("unexpected exposed ports: %+v", stored.ExposedPorts)
				}
			},
		},
		{
			name: "delete_by_id",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-delete-id", Name: "delete-id", Image: "image-delete-id"})

				resp, httpResp, err := env.api.SandboxAPI.DeleteSandbox(env.ctx, seed.ID).Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				assertSandboxMissing(t, env, seed.ID)
			},
		},
		{
			name: "delete_by_name",
			run: func(t *testing.T, env *daytonaContractEnv) {
				const sandboxName = "delete-name"
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-delete-name", Name: sandboxName, Image: "image-delete-name"})

				resp, httpResp, err := env.api.SandboxAPI.DeleteSandbox(env.ctx, sandboxName).Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				assertSandboxMissing(t, env, seed.ID)
			},
		},
	}

	runContractCases(t, cases)
}

func TestDaytonaGeneratedSnapshotContracts(t *testing.T) {
	cases := []contractCase{
		{
			name: "create_snapshot_from_sandbox",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-snap-create", Name: "snap-create"})

				resp, httpResp, err := env.api.SandboxAPI.CreateSandboxSnapshot(env.ctx, seed.ID).
					CreateSandboxSnapshot(*apiclient.NewCreateSandboxSnapshot("generated-snapshot")).
					Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				snapshot, err := env.store.GetSnapshot(env.ctx, "generated-snapshot")
				if err != nil {
					t.Fatalf("store.GetSnapshot(generated-snapshot) error = %v", err)
				}
				if snapshot.SourceSandboxID != seed.ID || strings.TrimSpace(snapshot.ImageID) == "" {
					t.Fatalf("unexpected snapshot metadata: %+v", snapshot)
				}
			},
		},
		{
			name: "create_snapshot_by_name_lookup",
			run: func(t *testing.T, env *daytonaContractEnv) {
				const sandboxName = "sandbox-name-lookup"
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-snap-name", Name: sandboxName})

				resp, httpResp, err := env.api.SandboxAPI.CreateSandboxSnapshot(env.ctx, sandboxName).
					CreateSandboxSnapshot(*apiclient.NewCreateSandboxSnapshot("snapshot-by-name")).
					Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				snapshot, err := env.store.GetSnapshot(env.ctx, "snapshot-by-name")
				if err != nil {
					t.Fatalf("store.GetSnapshot(snapshot-by-name) error = %v", err)
				}
				if snapshot.SourceSandboxID != seed.ID || resp.GetId() != seed.ID {
					t.Fatalf("unexpected snapshot result: snapshot=%+v resp.ID=%q", snapshot, resp.GetId())
				}
			},
		},
		{
			name: "snapshot_create_conflict_across_sandboxes",
			run: func(t *testing.T, env *daytonaContractEnv) {
				first := env.seedSandbox(contractSandboxSeed{ID: "sb-conflict-one", Name: "conflict-one"})
				second := env.seedSandbox(contractSandboxSeed{ID: "sb-conflict-two", Name: "conflict-two"})

				_, _, err := env.api.SandboxAPI.CreateSandboxSnapshot(env.ctx, first.ID).
					CreateSandboxSnapshot(*apiclient.NewCreateSandboxSnapshot("shared-snapshot")).
					Execute()
				if err != nil {
					t.Fatalf("initial CreateSandboxSnapshot() error = %v", err)
				}

				_, httpResp, err := env.api.SandboxAPI.CreateSandboxSnapshot(env.ctx, second.ID).
					CreateSandboxSnapshot(*apiclient.NewCreateSandboxSnapshot("shared-snapshot")).
					Execute()
				assertGeneratedAPIErrorStatus(t, httpResp, err, http.StatusConflict)
			},
		},
		{
			name: "snapshot_create_repeated_for_same_sandbox_is_idempotent",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sb-idempotent-snapshot", Name: "idempotent-snapshot"})

				_, _, err := env.api.SandboxAPI.CreateSandboxSnapshot(env.ctx, seed.ID).
					CreateSandboxSnapshot(*apiclient.NewCreateSandboxSnapshot("idempotent")).
					Execute()
				if err != nil {
					t.Fatalf("first CreateSandboxSnapshot() error = %v", err)
				}

				resp, httpResp, err := env.api.SandboxAPI.CreateSandboxSnapshot(env.ctx, seed.ID).
					CreateSandboxSnapshot(*apiclient.NewCreateSandboxSnapshot("idempotent")).
					Execute()
				mustGeneratedSandboxSuccess(t, resp, httpResp, err)

				snapshot, err := env.store.GetSnapshot(env.ctx, "idempotent")
				if err != nil {
					t.Fatalf("store.GetSnapshot(idempotent) error = %v", err)
				}
				if snapshot.SourceSandboxID != seed.ID {
					t.Fatalf("snapshot.SourceSandboxID = %q, want %q", snapshot.SourceSandboxID, seed.ID)
				}
			},
		},
		{
			name: "list_snapshots_defaults",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSnapshot(contractSnapshotSeed{Name: "alpha", Image: "snapshots/alpha:v1", ImageID: "sha256:alpha", SourceSandboxID: "sb-alpha", CreatedAt: time.Now().UTC().Add(-time.Hour)})
				env.seedSnapshot(contractSnapshotSeed{Name: "beta", Image: "snapshots/beta:v1", ImageID: "sha256:beta", SourceSandboxID: "sb-beta", CreatedAt: time.Now().UTC()})

				resp, httpResp, err := env.api.SnapshotsAPI.GetAllSnapshots(env.ctx).
					XDaytonaOrganizationID(contractOrgID).
					Execute()
				if err != nil {
					t.Fatalf("GetAllSnapshots() error = %v", err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("GetAllSnapshots() status = %+v", httpResp)
				}
				if resp.GetPage() != 1 || resp.GetTotal() != 2 || len(resp.GetItems()) != 2 {
					t.Fatalf("unexpected pagination: page=%v total=%v len=%d", resp.GetPage(), resp.GetTotal(), len(resp.GetItems()))
				}
				if resp.GetItems()[0].GetName() != "beta" || resp.GetItems()[1].GetName() != "alpha" {
					t.Fatalf("unexpected default ordering: %q then %q", resp.GetItems()[0].GetName(), resp.GetItems()[1].GetName())
				}
			},
		},
		{
			name: "list_snapshots_by_name",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSnapshot(contractSnapshotSeed{Name: "alpha-snapshot", Image: "snapshots/alpha:v1", ImageID: "sha256:alpha-snapshot", SourceSandboxID: "sb-a"})
				env.seedSnapshot(contractSnapshotSeed{Name: "beta-snapshot", Image: "snapshots/beta:v1", ImageID: "sha256:beta-snapshot", SourceSandboxID: "sb-b"})

				resp, httpResp, err := env.api.SnapshotsAPI.GetAllSnapshots(env.ctx).Name("alpha").Execute()
				if err != nil {
					t.Fatalf("GetAllSnapshots(Name) error = %v", err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("GetAllSnapshots(Name) status = %+v", httpResp)
				}
				if len(resp.GetItems()) != 1 || resp.GetItems()[0].GetName() != "alpha-snapshot" {
					t.Fatalf("unexpected filtered snapshots: %+v", resp.GetItems())
				}
			},
		},
		{
			name: "list_snapshots_sort_name_asc",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSnapshot(contractSnapshotSeed{Name: "beta", Image: "snapshots/beta:v1", ImageID: "sha256:beta", SourceSandboxID: "sb-beta"})
				env.seedSnapshot(contractSnapshotSeed{Name: "alpha", Image: "snapshots/alpha:v1", ImageID: "sha256:alpha", SourceSandboxID: "sb-alpha"})

				resp, httpResp, err := env.api.SnapshotsAPI.GetAllSnapshots(env.ctx).
					Sort("name").
					Order("asc").
					Execute()
				if err != nil {
					t.Fatalf("GetAllSnapshots(Sort=name,Order=asc) error = %v", err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("GetAllSnapshots(Sort=name,Order=asc) status = %+v", httpResp)
				}
				if len(resp.GetItems()) != 2 || resp.GetItems()[0].GetName() != "alpha" || resp.GetItems()[1].GetName() != "beta" {
					t.Fatalf("unexpected name ordering: %+v", resp.GetItems())
				}
			},
		},
		{
			name: "list_snapshots_sort_created_desc",
			run: func(t *testing.T, env *daytonaContractEnv) {
				now := time.Now().UTC().Round(time.Second)
				env.seedSnapshot(contractSnapshotSeed{Name: "old", Image: "snapshots/old:v1", ImageID: "sha256:old", SourceSandboxID: "sb-old", CreatedAt: now.Add(-time.Hour)})
				env.seedSnapshot(contractSnapshotSeed{Name: "new", Image: "snapshots/new:v1", ImageID: "sha256:new", SourceSandboxID: "sb-new", CreatedAt: now})

				resp, httpResp, err := env.api.SnapshotsAPI.GetAllSnapshots(env.ctx).
					Sort("createdAt").
					Order("desc").
					Execute()
				if err != nil {
					t.Fatalf("GetAllSnapshots(Sort=createdAt,Order=desc) error = %v", err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("GetAllSnapshots(Sort=createdAt,Order=desc) status = %+v", httpResp)
				}
				if len(resp.GetItems()) != 2 || resp.GetItems()[0].GetName() != "new" {
					t.Fatalf("unexpected createdAt ordering: %+v", resp.GetItems())
				}
			},
		},
		{
			name: "list_snapshots_page_limit",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSnapshot(contractSnapshotSeed{Name: "alpha", Image: "snapshots/alpha:v1", ImageID: "sha256:alpha", SourceSandboxID: "sb-alpha"})
				env.seedSnapshot(contractSnapshotSeed{Name: "beta", Image: "snapshots/beta:v1", ImageID: "sha256:beta", SourceSandboxID: "sb-beta"})

				resp, httpResp, err := env.api.SnapshotsAPI.GetAllSnapshots(env.ctx).
					Sort("name").
					Order("asc").
					Page(2).
					Limit(1).
					Execute()
				if err != nil {
					t.Fatalf("GetAllSnapshots(Page=2,Limit=1) error = %v", err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("GetAllSnapshots(Page=2,Limit=1) status = %+v", httpResp)
				}
				if resp.GetPage() != 2 || resp.GetTotalPages() != 2 || len(resp.GetItems()) != 1 || resp.GetItems()[0].GetName() != "beta" {
					t.Fatalf("unexpected paginated snapshots: %+v", resp)
				}
			},
		},
		{
			name: "list_snapshots_invalid_sort",
			run: func(t *testing.T, env *daytonaContractEnv) {
				_, httpResp, err := env.api.SnapshotsAPI.GetAllSnapshots(env.ctx).Sort("size").Execute()
				assertGeneratedAPIErrorStatus(t, httpResp, err, http.StatusBadRequest)
			},
		},
		{
			name: "list_snapshots_invalid_order",
			run: func(t *testing.T, env *daytonaContractEnv) {
				_, httpResp, err := env.api.SnapshotsAPI.GetAllSnapshots(env.ctx).Order("sideways").Execute()
				assertGeneratedAPIErrorStatus(t, httpResp, err, http.StatusBadRequest)
			},
		},
		{
			name: "list_snapshots_invalid_limit",
			run: func(t *testing.T, env *daytonaContractEnv) {
				_, httpResp, err := env.api.SnapshotsAPI.GetAllSnapshots(env.ctx).Limit(201).Execute()
				assertGeneratedAPIErrorStatus(t, httpResp, err, http.StatusBadRequest)
			},
		},
		{
			name: "get_snapshot_by_id",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSnapshot(contractSnapshotSeed{Name: "lookup-id", Image: "snapshots/lookup-id:v1", ImageID: "sha256:lookup-id", SourceSandboxID: "sb-lookup-id"})

				resp, httpResp, err := env.api.SnapshotsAPI.GetSnapshot(env.ctx, seed.ImageID).Execute()
				if err != nil {
					t.Fatalf("GetSnapshot(%s) error = %v", seed.ImageID, err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("GetSnapshot(%s) status = %+v", seed.ImageID, httpResp)
				}
				if resp.GetId() != seed.ImageID || resp.GetName() != seed.Name {
					t.Fatalf("unexpected snapshot payload: id=%q name=%q", resp.GetId(), resp.GetName())
				}
			},
		},
		{
			name: "get_snapshot_by_name",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSnapshot(contractSnapshotSeed{Name: "lookup-name", Image: "snapshots/lookup-name:v1", ImageID: "sha256:lookup-name", SourceSandboxID: "sb-lookup-name"})

				resp, httpResp, err := env.api.SnapshotsAPI.GetSnapshot(env.ctx, seed.Name).Execute()
				if err != nil {
					t.Fatalf("GetSnapshot(%s) error = %v", seed.Name, err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("GetSnapshot(%s) status = %+v", seed.Name, httpResp)
				}
				if resp.GetId() != seed.ImageID || resp.GetName() != seed.Name {
					t.Fatalf("unexpected snapshot payload: id=%q name=%q", resp.GetId(), resp.GetName())
				}
			},
		},
		{
			name: "get_snapshot_missing",
			run: func(t *testing.T, env *daytonaContractEnv) {
				_, httpResp, err := env.api.SnapshotsAPI.GetSnapshot(env.ctx, "missing-snapshot").Execute()
				assertGeneratedAPIErrorStatus(t, httpResp, err, http.StatusNotFound)
			},
		},
		{
			name: "delete_snapshot_by_id",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSnapshot(contractSnapshotSeed{Name: "delete-by-id", Image: "snapshots/delete-by-id:v1", ImageID: "sha256:delete-by-id", SourceSandboxID: "sb-delete-by-id"})

				httpResp, err := env.api.SnapshotsAPI.RemoveSnapshot(env.ctx, seed.ImageID).Execute()
				if err != nil {
					t.Fatalf("RemoveSnapshot(%s) error = %v", seed.ImageID, err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("RemoveSnapshot(%s) status = %+v", seed.ImageID, httpResp)
				}

				assertSnapshotMissing(t, env, seed.Name)
				assertRemovedImage(t, env, seed.Image)
			},
		},
		{
			name: "delete_snapshot_by_name",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSnapshot(contractSnapshotSeed{Name: "delete-by-name", Image: "snapshots/delete-by-name:v1", ImageID: "sha256:delete-by-name", SourceSandboxID: "sb-delete-by-name"})

				httpResp, err := env.api.SnapshotsAPI.RemoveSnapshot(env.ctx, seed.Name).Execute()
				if err != nil {
					t.Fatalf("RemoveSnapshot(%s) error = %v", seed.Name, err)
				}
				if httpResp == nil || httpResp.StatusCode != http.StatusOK {
					t.Fatalf("RemoveSnapshot(%s) status = %+v", seed.Name, httpResp)
				}

				assertSnapshotMissing(t, env, seed.Name)
				assertRemovedImage(t, env, seed.Image)
			},
		},
		{
			name: "delete_snapshot_missing",
			run: func(t *testing.T, env *daytonaContractEnv) {
				httpResp, err := env.api.SnapshotsAPI.RemoveSnapshot(env.ctx, "missing-snapshot").Execute()
				assertGeneratedAPIErrorStatus(t, httpResp, err, http.StatusNotFound)
			},
		},
	}

	runContractCases(t, cases)
}

func TestDaytonaSDKContracts(t *testing.T) {
	cases := []contractCase{
		{
			name: "client_create_from_image",
			run: func(t *testing.T, env *daytonaContractEnv) {
				sandbox, err := env.sdk.Create(env.ctx, sdktypes.ImageParams{
					SandboxBaseParams: sdktypes.SandboxBaseParams{
						Name:     "sdk-image",
						User:     "coder",
						Labels:   map[string]string{"team": "sdk"},
						EnvVars:  map[string]string{"APP_ENV": "sdk"},
						Language: sdktypes.CodeLanguagePython,
					},
					Image:     "python:3.12",
					Resources: &sdktypes.Resources{CPU: 2, Memory: 4, Disk: 20},
				})
				if err != nil {
					t.Fatalf("sdk.Create(ImageParams) error = %v", err)
				}
				stored, err := env.store.Get(env.ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", sandbox.ID, err)
				}
				meta, err := env.loadDaytonaMeta(sandbox.ID)
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", sandbox.ID, err)
				}
				if stored.Image != "python:3.12" || stored.MemoryMB != 4096 || stored.DiskGB != 20 {
					t.Fatalf("unexpected stored sandbox: %+v", stored)
				}
				if meta.Name != "sdk-image" || meta.User != "coder" || meta.Labels["team"] != "sdk" {
					t.Fatalf("unexpected stored metadata: %+v", meta)
				}
			},
		},
		{
			name: "client_create_from_snapshot",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSnapshot(contractSnapshotSeed{Name: "sdk-base-snapshot", Image: "snapshots/sdk-base:v1", ImageID: "sha256:sdk-base", SourceSandboxID: "seed-source"})

				sandbox, err := env.sdk.Create(env.ctx, sdktypes.SnapshotParams{
					SandboxBaseParams: sdktypes.SandboxBaseParams{Name: "sdk-from-snapshot"},
					Snapshot:          "sdk-base-snapshot",
				})
				if err != nil {
					t.Fatalf("sdk.Create(SnapshotParams) error = %v", err)
				}
				stored, err := env.store.Get(env.ctx, sandbox.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", sandbox.ID, err)
				}
				meta, err := env.loadDaytonaMeta(sandbox.ID)
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", sandbox.ID, err)
				}
				// stored.Image is the resolved image from the snapshot row;
				// the meta.Snapshot field preserves the caller-supplied name.
				if stored.Image != "snapshots/sdk-base:v1" || valueOrEmpty(meta.Snapshot) != "sdk-base-snapshot" {
					t.Fatalf("snapshot contract not preserved: stored=%+v meta=%+v", stored, meta)
				}
			},
		},
		{
			name: "client_get_by_id",
			run: func(t *testing.T, env *daytonaContractEnv) {
				const sandboxName = "sdk-get-id"
				seed := env.seedSandbox(contractSandboxSeed{ID: "sdk-get-id", Name: sandboxName})

				sandbox, err := env.sdk.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("sdk.Get(%s) error = %v", seed.ID, err)
				}
				if sandbox.ID != seed.ID || sandbox.Name != sandboxName {
					t.Fatalf("unexpected sandbox payload: %+v", sandbox)
				}
			},
		},
		{
			name: "client_get_by_name",
			run: func(t *testing.T, env *daytonaContractEnv) {
				const sandboxName = "sdk-get-name"
				seed := env.seedSandbox(contractSandboxSeed{ID: "sdk-get-name", Name: sandboxName})

				sandbox, err := env.sdk.Get(env.ctx, sandboxName)
				if err != nil {
					t.Fatalf("sdk.Get(%s) error = %v", sandboxName, err)
				}
				if sandbox.ID != seed.ID || sandbox.Name != sandboxName {
					t.Fatalf("unexpected sandbox payload: %+v", sandbox)
				}
			},
		},
		{
			name: "client_list_defaults",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSandbox(contractSandboxSeed{ID: "sdk-list-one", Name: "sdk-list-one", CreatedAt: time.Now().UTC().Add(-time.Hour)})
				env.seedSandbox(contractSandboxSeed{ID: "sdk-list-two", Name: "sdk-list-two", CreatedAt: time.Now().UTC()})

				result, err := env.sdk.List(env.ctx, nil, nil, nil)
				if err != nil {
					t.Fatalf("sdk.List(nil,nil,nil) error = %v", err)
				}
				if result.Page != 1 || result.Total != 2 || len(result.Items) != 2 {
					t.Fatalf("unexpected list result: %+v", result)
				}
			},
		},
		{
			name: "client_list_filtered_by_labels",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSandbox(contractSandboxSeed{ID: "sdk-label-api", Name: "sdk-label-api", Labels: map[string]string{"team": "api"}})
				env.seedSandbox(contractSandboxSeed{ID: "sdk-label-web", Name: "sdk-label-web", Labels: map[string]string{"team": "web"}})

				result, err := env.sdk.List(env.ctx, map[string]string{"team": "api"}, nil, nil)
				if err != nil {
					t.Fatalf("sdk.List(labels) error = %v", err)
				}
				if len(result.Items) != 1 || result.Items[0].Name != "sdk-label-api" {
					t.Fatalf("unexpected filtered sandboxes: %+v", result.Items)
				}
			},
		},
		{
			name: "client_list_paginated",
			run: func(t *testing.T, env *daytonaContractEnv) {
				now := time.Now().UTC().Round(time.Second)
				env.seedSandbox(contractSandboxSeed{ID: "sdk-page-one", Name: "sdk-page-one", CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour), LastActiveAt: now.Add(-time.Hour)})
				env.seedSandbox(contractSandboxSeed{ID: "sdk-page-two", Name: "sdk-page-two", CreatedAt: now, UpdatedAt: now, LastActiveAt: now})

				page, limit := 2, 1
				result, err := env.sdk.List(env.ctx, nil, &page, &limit)
				if err != nil {
					t.Fatalf("sdk.List(page,limit) error = %v", err)
				}
				if result.Page != 2 || result.TotalPages != 2 || len(result.Items) != 1 || result.Items[0].Name != "sdk-page-one" {
					t.Fatalf("unexpected paginated sandboxes: %+v", result)
				}
			},
		},
		{
			name: "client_list_rejects_invalid_page",
			run: func(t *testing.T, env *daytonaContractEnv) {
				page := 0
				_, err := env.sdk.List(env.ctx, nil, &page, nil)
				assertDaytonaErrorContains(t, err, "page must be a positive integer")
			},
		},
		{
			name: "client_list_rejects_invalid_limit",
			run: func(t *testing.T, env *daytonaContractEnv) {
				limit := 0
				_, err := env.sdk.List(env.ctx, nil, nil, &limit)
				assertDaytonaErrorContains(t, err, "limit must be a positive integer")
			},
		},
		{
			name: "sandbox_start",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sdk-start", Name: "sdk-start", Status: models.SandboxStatusStopped})

				sandbox, err := env.sdk.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("sdk.Get(%s) error = %v", seed.ID, err)
				}
				if err := sandbox.Start(env.ctx); err != nil {
					t.Fatalf("sandbox.Start() error = %v", err)
				}
				stored, err := env.store.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", seed.ID, err)
				}
				if stored.Status != models.SandboxStatusStarted {
					t.Fatalf("stored.Status = %q, want %q", stored.Status, models.SandboxStatusStarted)
				}
			},
		},
		{
			name: "sandbox_stop",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sdk-stop", Name: "sdk-stop", Status: models.SandboxStatusStarted})

				sandbox, err := env.sdk.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("sdk.Get(%s) error = %v", seed.ID, err)
				}
				if err := sandbox.Stop(env.ctx); err != nil {
					t.Fatalf("sandbox.Stop() error = %v", err)
				}
				stored, err := env.store.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", seed.ID, err)
				}
				if stored.Status != models.SandboxStatusStopped {
					t.Fatalf("stored.Status = %q, want %q", stored.Status, models.SandboxStatusStopped)
				}
			},
		},
		{
			name: "sandbox_set_labels",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sdk-set-labels", Name: "sdk-set-labels"})

				sandbox, err := env.sdk.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("sdk.Get(%s) error = %v", seed.ID, err)
				}
				if err := sandbox.SetLabels(env.ctx, map[string]string{"component": "sdk"}); err != nil {
					t.Fatalf("sandbox.SetLabels() error = %v", err)
				}
				meta, err := env.loadDaytonaMeta(seed.ID)
				if err != nil {
					t.Fatalf("loadDaytonaMeta(%s) error = %v", seed.ID, err)
				}
				if meta.Labels["component"] != "sdk" {
					t.Fatalf("stored labels = %+v", meta.Labels)
				}
			},
		},
		{
			name: "sandbox_resize",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sdk-resize", Name: "sdk-resize", CPU: 2, MemoryMB: 2048, DiskGB: 10})

				sandbox, err := env.sdk.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("sdk.Get(%s) error = %v", seed.ID, err)
				}
				if err := sandbox.Resize(env.ctx, &sdktypes.Resources{CPU: 4, Memory: 8, Disk: 50}); err != nil {
					t.Fatalf("sandbox.Resize() error = %v", err)
				}
				stored, err := env.store.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("store.Get(%s) error = %v", seed.ID, err)
				}
				if stored.CPU != 4 || stored.MemoryMB != 8192 || stored.DiskGB != 50 {
					t.Fatalf("unexpected resized sandbox: %+v", stored)
				}
			},
		},
		{
			name: "sandbox_get_preview_link",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sdk-preview", Name: "sdk-preview"})

				sandbox, err := env.sdk.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("sdk.Get(%s) error = %v", seed.ID, err)
				}
				preview, err := sandbox.GetPreviewLink(env.ctx, 3000)
				if err != nil {
					t.Fatalf("sandbox.GetPreviewLink() error = %v", err)
				}
				wantURL := fmt.Sprintf("http://%s/%s/proxy/%d/", contractPublicHost, seed.ID, 3000)
				if preview.URL != wantURL || preview.Token != "" {
					t.Fatalf("unexpected preview link: %+v", preview)
				}
			},
		},
		{
			name: "sandbox_delete",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sdk-delete", Name: "sdk-delete", Image: "image-sdk-delete"})

				sandbox, err := env.sdk.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("sdk.Get(%s) error = %v", seed.ID, err)
				}
				if err := sandbox.Delete(env.ctx); err != nil {
					t.Fatalf("sandbox.Delete() error = %v", err)
				}
				assertSandboxMissing(t, env, seed.ID)
			},
		},
		{
			name: "sandbox_experimental_create_snapshot",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSandbox(contractSandboxSeed{ID: "sdk-snapshot-source", Name: "sdk-snapshot-source"})

				sandbox, err := env.sdk.Get(env.ctx, seed.ID)
				if err != nil {
					t.Fatalf("sdk.Get(%s) error = %v", seed.ID, err)
				}
				if err := sandbox.ExperimentalCreateSnapshot(env.ctx, "sdk-created-snapshot"); err != nil {
					t.Fatalf("sandbox.ExperimentalCreateSnapshot() error = %v", err)
				}
				snapshot, err := env.store.GetSnapshot(env.ctx, "sdk-created-snapshot")
				if err != nil {
					t.Fatalf("store.GetSnapshot(sdk-created-snapshot) error = %v", err)
				}
				if snapshot.SourceSandboxID != seed.ID {
					t.Fatalf("snapshot.SourceSandboxID = %q, want %q", snapshot.SourceSandboxID, seed.ID)
				}
			},
		},
		{
			name: "snapshot_list_defaults",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSnapshot(contractSnapshotSeed{Name: "sdk-alpha", Image: "snapshots/sdk-alpha:v1", ImageID: "sha256:sdk-alpha", SourceSandboxID: "sb-sdk-alpha", CreatedAt: time.Now().UTC().Add(-time.Hour)})
				env.seedSnapshot(contractSnapshotSeed{Name: "sdk-beta", Image: "snapshots/sdk-beta:v1", ImageID: "sha256:sdk-beta", SourceSandboxID: "sb-sdk-beta", CreatedAt: time.Now().UTC()})

				result, err := env.sdk.Snapshot.List(env.ctx, nil, nil)
				if err != nil {
					t.Fatalf("sdk.Snapshot.List(nil,nil) error = %v", err)
				}
				if result.Page != 1 || result.Total != 2 || len(result.Items) != 2 || result.Items[0].Name != "sdk-beta" {
					t.Fatalf("unexpected snapshot list result: %+v", result)
				}
			},
		},
		{
			name: "snapshot_list_paginated",
			run: func(t *testing.T, env *daytonaContractEnv) {
				env.seedSnapshot(contractSnapshotSeed{Name: "sdk-alpha", Image: "snapshots/sdk-alpha:v1", ImageID: "sha256:sdk-alpha", SourceSandboxID: "sb-sdk-alpha"})
				env.seedSnapshot(contractSnapshotSeed{Name: "sdk-beta", Image: "snapshots/sdk-beta:v1", ImageID: "sha256:sdk-beta", SourceSandboxID: "sb-sdk-beta"})

				page, limit := 2, 1
				result, err := env.sdk.Snapshot.List(env.ctx, &page, &limit)
				if err != nil {
					t.Fatalf("sdk.Snapshot.List(page,limit) error = %v", err)
				}
				if result.Page != 2 || result.TotalPages != 2 || len(result.Items) != 1 || result.Items[0].Name != "sdk-alpha" {
					t.Fatalf("unexpected paginated snapshot list result: %+v", result)
				}
			},
		},
		{
			name: "snapshot_get_by_name",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSnapshot(contractSnapshotSeed{Name: "sdk-lookup-name", Image: "snapshots/sdk-lookup-name:v1", ImageID: "sha256:sdk-lookup-name", SourceSandboxID: "sb-sdk-lookup-name"})

				snapshot, err := env.sdk.Snapshot.Get(env.ctx, seed.Name)
				if err != nil {
					t.Fatalf("sdk.Snapshot.Get(%s) error = %v", seed.Name, err)
				}
				if snapshot.ID != seed.ImageID || snapshot.Name != seed.Name {
					t.Fatalf("unexpected snapshot payload: %+v", snapshot)
				}
			},
		},
		{
			name: "snapshot_get_by_id",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSnapshot(contractSnapshotSeed{Name: "sdk-lookup-id", Image: "snapshots/sdk-lookup-id:v1", ImageID: "sha256:sdk-lookup-id", SourceSandboxID: "sb-sdk-lookup-id"})

				snapshot, err := env.sdk.Snapshot.Get(env.ctx, seed.ImageID)
				if err != nil {
					t.Fatalf("sdk.Snapshot.Get(%s) error = %v", seed.ImageID, err)
				}
				if snapshot.ID != seed.ImageID || snapshot.Name != seed.Name {
					t.Fatalf("unexpected snapshot payload: %+v", snapshot)
				}
			},
		},
		{
			name: "snapshot_delete",
			run: func(t *testing.T, env *daytonaContractEnv) {
				seed := env.seedSnapshot(contractSnapshotSeed{Name: "sdk-delete-snapshot", Image: "snapshots/sdk-delete:v1", ImageID: "sha256:sdk-delete", SourceSandboxID: "sb-sdk-delete"})

				snapshot, err := env.sdk.Snapshot.Get(env.ctx, seed.Name)
				if err != nil {
					t.Fatalf("sdk.Snapshot.Get(%s) error = %v", seed.Name, err)
				}
				if err := env.sdk.Snapshot.Delete(env.ctx, snapshot); err != nil {
					t.Fatalf("sdk.Snapshot.Delete() error = %v", err)
				}
				assertSnapshotMissing(t, env, seed.Name)
				assertRemovedImage(t, env, seed.Image)
			},
		},
	}

	runContractCases(t, cases)
}

func runContractCases(t *testing.T, cases []contractCase) {
	t.Helper()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			env := newDaytonaContractEnv(t)
			tc.run(t, env)
		})
	}
}

func newGeneratedCreateRequest(image string) *apiclient.CreateSandbox {
	req := apiclient.NewCreateSandbox()
	req.BuildInfo = apiclient.NewCreateBuildInfo("FROM " + image)
	return req
}

func labelJSON(labels map[string]string) string {
	data, err := json.Marshal(labels)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func ptrFloat32(value float32) *float32 {
	return &value
}

func mustGeneratedSandboxSuccess(t *testing.T, resp *apiclient.Sandbox, httpResp *http.Response, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected generated client error = %v", err)
	}
	if httpResp == nil || httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		t.Fatalf("unexpected HTTP response = %+v", httpResp)
	}
	if resp == nil {
		t.Fatal("unexpected nil sandbox response")
	}
}

func assertGeneratedAPIErrorStatus(t *testing.T, httpResp *http.Response, err error, wantStatus int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected generated client error with status %d", wantStatus)
	}
	if httpResp == nil {
		t.Fatalf("expected HTTP response with status %d, got nil", wantStatus)
	}
	if httpResp.StatusCode != wantStatus {
		t.Fatalf("httpResp.StatusCode = %d, want %d; err=%v", httpResp.StatusCode, wantStatus, err)
	}
}

func assertSandboxMissing(t *testing.T, env *daytonaContractEnv, sandboxID string) {
	t.Helper()
	if _, err := env.store.Get(env.ctx, sandboxID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected sandbox %q to be missing, got err=%v", sandboxID, err)
	}
}

func assertSnapshotMissing(t *testing.T, env *daytonaContractEnv, snapshotName string) {
	t.Helper()
	if _, err := env.store.GetSnapshot(env.ctx, snapshotName); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected snapshot %q to be missing, got err=%v", snapshotName, err)
	}
}

func assertRemovedImage(t *testing.T, env *daytonaContractEnv, image string) {
	t.Helper()
	removed := env.removedImages()
	for _, candidate := range removed {
		if candidate == image {
			return
		}
	}
	t.Fatalf("expected removed images %v to contain %q", removed, image)
}

func assertDaytonaErrorContains(t *testing.T, err error, wantSubstring string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", wantSubstring)
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("error %q does not contain %q", err.Error(), wantSubstring)
	}
}
