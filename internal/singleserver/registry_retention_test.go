package singleserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func digestOf(name string) string {
	return "sha256:" + fmt.Sprintf("%064x", []byte(name))[:64]
}

func TestPlanRegistryRetentionKeepSet(t *testing.T) {
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	var tags []registryTag
	children := map[string][]string{}
	for i := 1; i <= 15; i++ {
		name := fmt.Sprintf("t%02d", i)
		digest := digestOf("idx-" + name)
		tags = append(tags, registryTag{Name: name, Digest: digest, Created: base.Add(time.Duration(i) * time.Hour)})
		children[digest] = []string{digestOf("img-" + name), digestOf("att-" + name)}
	}
	// latest points at the newest build.
	tags = append(tags, registryTag{Name: "latest", Digest: digestOf("idx-t15"), Created: base.Add(15 * time.Hour)})
	// t05 is an old tag on the same digest as the kept t12: the digest stays.
	tags[4].Digest = digestOf("idx-t12")
	// t04's platform manifest is also a child of the kept t10.
	children[digestOf("idx-t04")] = []string{digestOf("img-t10"), digestOf("att-t04")}
	children[digestOf("idx-t10")] = []string{digestOf("img-t10"), digestOf("att-t10")}
	// An old tag whose push time could not be read is kept.
	tags = append(tags, registryTag{Name: "unknown", Digest: digestOf("idx-unknown")})

	pinnedTags := map[string]bool{"t02": true}                  // the running container runs an old tag
	pinnedDigests := map[string]bool{digestOf("idx-t03"): true} // the newest stopped container, by RepoDigest

	plan := planRegistryRetention(tags, 10, pinnedTags, pinnedDigests, children)

	gotKeep := append([]string(nil), plan.KeepTags...)
	sort.Strings(gotKeep)
	wantKeep := []string{"latest", "t02", "t03", "t05", "t06", "t07", "t08", "t09", "t10", "t11", "t12", "t13", "t14", "t15", "unknown"}
	if strings.Join(gotKeep, ",") != strings.Join(wantKeep, ",") {
		t.Fatalf("kept tags = %v, want %v", gotKeep, wantKeep)
	}

	wantDelete := []string{
		digestOf("idx-t04"), digestOf("idx-t01"), // dropped indexes, newest first
		digestOf("att-t04"), digestOf("img-t01"), digestOf("att-t01"), // then their unshared children
	}
	if strings.Join(plan.Delete, "\n") != strings.Join(wantDelete, "\n") {
		t.Fatalf("delete = %v\nwant %v", plan.Delete, wantDelete)
	}
	for _, digest := range plan.Delete {
		if plan.KeepDigests[digest] {
			t.Fatalf("plan deletes kept digest %s", digest)
		}
	}
	for _, kept := range []string{digestOf("idx-t12"), digestOf("img-t10"), digestOf("idx-t03"), digestOf("img-t03"), digestOf("idx-t02")} {
		if !plan.KeepDigests[kept] {
			t.Fatalf("expected %s to be kept", kept)
		}
	}
}

func TestPlanRegistryRetentionKeepsTagsWithSharedPushTime(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	tags := []registryTag{
		{Name: "a", Digest: digestOf("a"), Created: epoch},
		{Name: "b", Digest: digestOf("b"), Created: epoch},
		{Name: "c", Digest: digestOf("c"), Created: epoch},
	}
	plan := planRegistryRetention(tags, 1, nil, nil, nil)
	if len(plan.Delete) != 0 {
		t.Fatalf("tags with the same push time cannot be ordered and must be kept, got delete %v", plan.Delete)
	}
}

func TestImageRefTagOrDigest(t *testing.T) {
	cases := []struct{ ref, tag, digest string }{
		{"127.0.0.1:5555/web:abc123", "abc123", ""},
		{"127.0.0.1:5555/web@sha256:deadbeef", "", "sha256:deadbeef"},
		{"127.0.0.1:5555/web-api:abc", "", ""},
		{"127.0.0.1:5555/other:abc", "", ""},
		{"web:abc", "abc", ""},
	}
	for _, tc := range cases {
		tag, digest := imageRefTagOrDigest(tc.ref, "web")
		if tag != tc.tag || digest != tc.digest {
			t.Fatalf("%s: got (%q, %q), want (%q, %q)", tc.ref, tag, digest, tc.tag, tc.digest)
		}
	}
}

func TestRegistryKeepTagsConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apps.yml")
	body := "apps:\n  - repo: acme/web\n    cleanup_after_deploy: true\n  - repo: acme/api\n    cleanup_after_deploy: true\n    registry_keep_tags: 5\n  - acme/site\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Apps[0].RegistryKeepTags != 10 || config.Apps[1].RegistryKeepTags != 5 || config.Apps[2].RegistryKeepTags != 0 {
		t.Fatalf("registry_keep_tags = %d, %d, %d", config.Apps[0].RegistryKeepTags, config.Apps[1].RegistryKeepTags, config.Apps[2].RegistryKeepTags)
	}
	if err := writeConfig(path, config); err != nil {
		t.Fatal(err)
	}
	written, _ := os.ReadFile(path)
	if string(written) != body {
		t.Fatalf("written config:\n%s\nwant:\n%s", written, body)
	}
	bad := AppConfig{Repo: "acme/web", CleanupAfterDeploy: true, RegistryKeepTags: -1}
	if err := bad.Normalize(); err == nil {
		t.Fatal("expected error for negative registry_keep_tags")
	}
}

// fakeRegistry serves the distribution API for one repository of buildx-style
// images: each tag is an OCI index with a platform manifest and an
// attestation manifest.
type fakeRegistry struct {
	mu             sync.Mutex
	repo           string
	tags           map[string]string // tag -> index digest
	manifests      map[string]string // digest -> body
	mediaTypes     map[string]string
	blobs          map[string]string
	deleteDisabled bool
	deleted        []string
}

func newFakeRegistry(repo string, count int, base time.Time) *fakeRegistry {
	r := &fakeRegistry{repo: repo, tags: map[string]string{}, manifests: map[string]string{}, mediaTypes: map[string]string{}, blobs: map[string]string{}}
	for i := 1; i <= count; i++ {
		name := fmt.Sprintf("sha%02d", i)
		idx, img, att, cfg := digestOf("idx-"+name), digestOf("img-"+name), digestOf("att-"+name), digestOf("cfg-"+name)
		r.manifests[idx] = fmt.Sprintf(`{"mediaType":%q,"manifests":[{"digest":%q,"platform":{"os":"linux","architecture":"amd64"}},{"digest":%q,"platform":{"os":"unknown","architecture":"unknown"},"annotations":{"vnd.docker.reference.type":"attestation-manifest"}}]}`, mediaTypeOCIIndex, img, att)
		r.mediaTypes[idx] = mediaTypeOCIIndex
		r.manifests[img] = fmt.Sprintf(`{"mediaType":%q,"config":{"digest":%q}}`, mediaTypeOCIManifest, cfg)
		r.mediaTypes[img] = mediaTypeOCIManifest
		r.manifests[att] = fmt.Sprintf(`{"mediaType":%q,"config":{"digest":%q}}`, mediaTypeOCIManifest, digestOf("attcfg-"+name))
		r.mediaTypes[att] = mediaTypeOCIManifest
		r.blobs[cfg] = fmt.Sprintf(`{"created":%q}`, base.Add(time.Duration(i)*time.Hour).Format(time.RFC3339Nano))
		r.tags[name] = idx
	}
	r.tags["latest"] = r.tags[fmt.Sprintf("sha%02d", count)]
	return r
}

func (r *fakeRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	prefix := "/v2/" + r.repo + "/"
	switch {
	case req.URL.Path == "/v2/":
		w.WriteHeader(http.StatusOK)
	case req.URL.Path == prefix+"tags/list":
		var names []string
		for name := range r.tags {
			names = append(names, name)
		}
		sort.Strings(names)
		_ = json.NewEncoder(w).Encode(map[string]any{"name": r.repo, "tags": names})
	case strings.HasPrefix(req.URL.Path, prefix+"manifests/"):
		ref := strings.TrimPrefix(req.URL.Path, prefix+"manifests/")
		digest := ref
		if tagged, ok := r.tags[ref]; ok {
			digest = tagged
		}
		body, ok := r.manifests[digest]
		if req.Method == http.MethodDelete {
			if r.deleteDisabled {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if !strings.HasPrefix(ref, "sha256:") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r.deleted = append(r.deleted, ref)
			delete(r.manifests, ref)
			for name, tagged := range r.tags {
				if tagged == ref {
					delete(r.tags, name)
				}
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", r.mediaTypes[digest])
		w.Header().Set("Docker-Content-Digest", digest)
		_, _ = w.Write([]byte(body))
	case strings.HasPrefix(req.URL.Path, prefix+"blobs/"):
		body, ok := r.blobs[strings.TrimPrefix(req.URL.Path, prefix+"blobs/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type fakeDocker struct {
	mu      sync.Mutex
	calls   []string
	ps      string
	inspect map[string]string
	// inspectErr maps an image to the output of a failing image inspect.
	inspectErr map[string]string
	failGC     bool
	failPS     bool
}

func (d *fakeDocker) run(_ context.Context, args ...string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, strings.Join(args, " "))
	switch {
	case args[0] == "ps":
		if d.failPS {
			return "Cannot connect to the Docker daemon", errors.New("exit status 1")
		}
		return d.ps, nil
	case args[0] == "image" && args[1] == "inspect":
		if out, ok := d.inspectErr[args[len(args)-1]]; ok {
			return out, errors.New("exit status 1")
		}
		return d.inspect[args[len(args)-1]], nil
	case args[0] == "inspect":
		return `["/etc/docker/registry/config.yml"]`, nil
	case args[0] == "exec":
		if d.failGC {
			return "failed to garbage collect: boom", errors.New("exit status 1")
		}
		return "web\nmarking manifest sha256:x\nblob eligible for deletion: sha256:a\nblob eligible for deletion: sha256:b\n", nil
	}
	return "", nil
}

func newRetentionManager(t *testing.T, registry *fakeRegistry, docker *fakeDocker) (*DeployManager, *bytes.Buffer) {
	t.Helper()
	t.Setenv("SINGLESERVER_STATE_DIR", t.TempDir())
	server := httptest.NewServer(registry)
	t.Cleanup(server.Close)
	var logs bytes.Buffer
	return &DeployManager{logger: log.New(&logs, "", 0), docker: docker.run, registryURL: server.URL}, &logs
}

func assertSafeDockerCalls(t *testing.T, calls []string) {
	t.Helper()
	for _, call := range calls {
		if strings.Contains(call, "volume") || strings.Contains(call, "--delete-untagged") || strings.Contains(call, " rm") || strings.Contains(call, "prune") {
			t.Fatalf("unsafe docker call: %q", call)
		}
	}
}

func TestRegistryRetentionDeletesOldIndexesAndChildrenThenGarbageCollects(t *testing.T) {
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	registry := newFakeRegistry("web", 14, base)
	docker := &fakeDocker{
		// Newest first: a running container on an old tag, an older stopped
		// one pinned by digest, and an even older stopped one that is not kept.
		ps: "running\t127.0.0.1:5555/web:sha02\nexited\t127.0.0.1:5555/web@" + digestOf("idx-sha03") + "\nexited\t127.0.0.1:5555/web:sha01\n",
		inspect: map[string]string{
			"127.0.0.1:5555/web:sha02":                    "127.0.0.1:5555/web@" + digestOf("idx-sha02") + "\n",
			"127.0.0.1:5555/web@" + digestOf("idx-sha03"): "127.0.0.1:5555/web@" + digestOf("idx-sha03") + "\n",
		},
	}
	m, logs := newRetentionManager(t, registry, docker)

	m.registryRetention(AppConfig{Name: "web", RegistryKeepTags: 10}, "run-r1")

	// Keep sha05..sha14 (newest 10), latest (= sha14), sha02 (running) and
	// sha03 (newest stopped). Delete sha01 and sha04 with their children.
	want := []string{
		digestOf("idx-sha04"), digestOf("idx-sha01"),
		digestOf("img-sha04"), digestOf("att-sha04"), digestOf("img-sha01"), digestOf("att-sha01"),
	}
	if strings.Join(registry.deleted, "\n") != strings.Join(want, "\n") {
		t.Fatalf("deleted:\n%s\nwant:\n%s", strings.Join(registry.deleted, "\n"), strings.Join(want, "\n"))
	}
	for _, kept := range []string{"sha02", "sha03", "sha05", "sha14", "latest"} {
		if _, ok := registry.tags[kept]; !ok {
			t.Fatalf("tag %s should still exist", kept)
		}
	}

	assertSafeDockerCalls(t, docker.calls)
	gc, restart := -1, -1
	for i, call := range docker.calls {
		switch call {
		case "exec singleserver-registry registry garbage-collect /etc/docker/registry/config.yml":
			gc = i
		case "restart singleserver-registry":
			restart = i
		}
	}
	if gc < 0 || restart < gc {
		t.Fatalf("expected plain garbage-collect then restart, calls:\n%s", strings.Join(docker.calls, "\n"))
	}
	if !strings.Contains(logs.String(), "[deploy:run-r1] registry retention: tags=15 kept=13 deleted_manifests=6 gc_blobs_deleted=2") {
		t.Fatalf("missing summary log:\n%s", logs.String())
	}
}

func TestRegistryRetentionSkipsWhenDeleteDisabled(t *testing.T) {
	registry := newFakeRegistry("web", 12, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	registry.deleteDisabled = true
	docker := &fakeDocker{}
	m, logs := newRetentionManager(t, registry, docker)

	m.registryRetention(AppConfig{Name: "web", RegistryKeepTags: 10}, "run-r2")

	if !strings.Contains(logs.String(), "[deploy:run-r2] registry retention skipped: delete web@") {
		t.Fatalf("missing skip warning:\n%s", logs.String())
	}
	for _, call := range docker.calls {
		if strings.HasPrefix(call, "exec") || strings.HasPrefix(call, "restart") {
			t.Fatalf("must not garbage-collect or restart when nothing was deleted: %q", call)
		}
	}
}

func TestRegistryRetentionGCFailureRestartsRegistryAndOnlyLogs(t *testing.T) {
	registry := newFakeRegistry("web", 12, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	docker := &fakeDocker{failGC: true}
	m, logs := newRetentionManager(t, registry, docker)

	// No return value: a failing retention cannot fail the deploy.
	m.registryRetention(AppConfig{Name: "web", RegistryKeepTags: 10}, "run-r3")

	if !strings.Contains(logs.String(), "[deploy:run-r3] registry retention failed") {
		t.Fatalf("missing failure log:\n%s", logs.String())
	}
	if docker.calls[len(docker.calls)-1] != "restart singleserver-registry" {
		t.Fatalf("registry must be restarted after a failed garbage-collect, calls:\n%s", strings.Join(docker.calls, "\n"))
	}
	assertSafeDockerCalls(t, docker.calls)
}

func TestRegistryRetentionDeletesNothingWhenContainersUnknown(t *testing.T) {
	registry := newFakeRegistry("web", 12, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	docker := &fakeDocker{failPS: true}
	m, logs := newRetentionManager(t, registry, docker)

	m.registryRetention(AppConfig{Name: "web", RegistryKeepTags: 10}, "run-r4")

	if len(registry.deleted) != 0 {
		t.Fatalf("deleted %v without knowing container images", registry.deleted)
	}
	if !strings.Contains(logs.String(), "registry retention failed") {
		t.Fatalf("missing failure log:\n%s", logs.String())
	}
}

func TestRegistryRetentionSkipsContainerWhoseImageIsGone(t *testing.T) {
	registry := newFakeRegistry("web", 14, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	docker := &fakeDocker{
		// The running container's image is present; the newest stopped
		// container's image was pruned locally.
		ps: "running\t127.0.0.1:5555/web:sha02\nexited\t127.0.0.1:5555/web:sha03\n",
		inspect: map[string]string{
			"127.0.0.1:5555/web:sha02": "127.0.0.1:5555/web@" + digestOf("idx-sha02") + "\n",
		},
		inspectErr: map[string]string{
			"127.0.0.1:5555/web:sha03": "Error: No such image: 127.0.0.1:5555/web:sha03",
		},
	}
	m, logs := newRetentionManager(t, registry, docker)

	m.registryRetention(AppConfig{Name: "web", RegistryKeepTags: 10}, "run-r5")

	if strings.Contains(logs.String(), "registry retention failed") {
		t.Fatalf("retention must not fail on a missing image:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "image 127.0.0.1:5555/web:sha03 of a container is gone locally") {
		t.Fatalf("missing warning for the gone image:\n%s", logs.String())
	}
	// sha02 stays pinned by the running container, sha03 by the stopped
	// container's own tag; only sha01 and sha04 are old and unpinned.
	for _, kept := range []string{"sha02", "sha03", "sha05", "sha14", "latest"} {
		if _, ok := registry.tags[kept]; !ok {
			t.Fatalf("tag %s should still exist", kept)
		}
	}
	for _, gone := range []string{"sha01", "sha04"} {
		if _, ok := registry.tags[gone]; ok {
			t.Fatalf("tag %s should have been deleted", gone)
		}
	}
	assertSafeDockerCalls(t, docker.calls)
}

func TestRegistryRetentionDeletesNothingWhenImageInspectFails(t *testing.T) {
	registry := newFakeRegistry("web", 12, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	docker := &fakeDocker{
		ps: "running\t127.0.0.1:5555/web:sha02\n",
		inspectErr: map[string]string{
			"127.0.0.1:5555/web:sha02": "Cannot connect to the Docker daemon",
		},
	}
	m, logs := newRetentionManager(t, registry, docker)

	m.registryRetention(AppConfig{Name: "web", RegistryKeepTags: 10}, "run-r6")

	if len(registry.deleted) != 0 {
		t.Fatalf("deleted %v although an image inspect failed", registry.deleted)
	}
	if !strings.Contains(logs.String(), "registry retention failed") {
		t.Fatalf("missing failure log:\n%s", logs.String())
	}
}

func TestRegistryRetentionSourceHasNoUnsafeCommands(t *testing.T) {
	body, err := os.ReadFile("registry_retention.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, forbidden := range []string{"volume", "--delete-untagged", "prune", `"rm"`, "/srv/storage"} {
			if strings.Contains(trimmed, forbidden) {
				t.Fatalf("registry_retention.go line %q contains %q", line, forbidden)
			}
		}
	}
}

func TestRegistryLockExclusiveWaitsForSharedHolders(t *testing.T) {
	t.Setenv("SINGLESERVER_STATE_DIR", t.TempDir())
	// Each acquire opens its own file description, so this behaves like a
	// daemon deploy and a CLI deploy in separate processes.
	releaseShared, err := acquireRegistryLock(false)
	if err != nil {
		t.Fatal(err)
	}
	releaseShared2, err := acquireRegistryLock(false)
	if err != nil {
		t.Fatal("two deploys must be able to push at once:", err)
	}

	acquired := make(chan func())
	go func() {
		release, err := acquireRegistryLock(true)
		if err != nil {
			t.Error(err)
			close(acquired)
			return
		}
		acquired <- release
	}()
	select {
	case <-acquired:
		t.Fatal("retention took the registry lock while a deploy held it")
	case <-time.After(200 * time.Millisecond):
	}
	releaseShared()
	releaseShared2()
	select {
	case release := <-acquired:
		if release == nil {
			t.Fatal("exclusive acquire failed")
		}
		defer release()
	case <-time.After(5 * time.Second):
		t.Fatal("retention never got the registry lock")
	}

	blocked := make(chan struct{})
	go func() {
		release, err := acquireRegistryLock(false)
		if err == nil {
			release()
		}
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("a deploy took the registry lock during retention")
	case <-time.After(200 * time.Millisecond):
	}
}
