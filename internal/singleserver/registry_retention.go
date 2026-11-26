package singleserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Registry retention trims an app's repository in the local registry
// (singleserver-registry) after a successful deploy. It keeps the newest
// registry_keep_tags tags, latest, and whatever the app's containers use. It
// deletes the other tags' manifests through the registry API and then runs a
// plain garbage-collect.
//
// It never runs garbage-collect with --delete-untagged. buildx pushes OCI image
// indexes whose platform and attestation manifests are untagged children, and
// registry 2.8's --delete-untagged removes those children even for indexes it
// keeps (distribution/distribution#3178), which breaks the kept images.
// Instead, the children that belong only to deleted indexes are deleted
// explicitly here.

const (
	registryContainer       = "singleserver-registry"
	defaultRegistryConfig   = "/etc/docker/registry/config.yml"
	registryRetentionLimit  = 15 * time.Minute
	registryReadyTimeout    = 30 * time.Second
	mediaTypeOCIIndex       = "application/vnd.oci.image.index.v1+json"
	mediaTypeDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
)

var errRegistryDeleteDisabled = errors.New("registry deletes are disabled (start singleserver-registry with REGISTRY_STORAGE_DELETE_ENABLED=true)")

// dockerCommandFunc runs `docker <args>` and returns its combined output.
type dockerCommandFunc func(ctx context.Context, args ...string) (string, error)

func runDockerCommand(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(out), err
}

func registryBaseURL() string {
	return strings.TrimRight(envDefault("SINGLESERVER_REGISTRY_URL", "http://127.0.0.1:5555"), "/")
}

// registryRetention trims the app's registry repository. Failures are only
// logged; the deploy has already succeeded.
func (m *DeployManager) registryRetention(app AppConfig, runID string) {
	start := time.Now()
	// Hold the registry lock exclusively: no deploy in any singleserver
	// process may push while manifests are deleted and blobs are
	// garbage-collected.
	release, err := acquireRegistryLock(true)
	if err != nil {
		m.logger.Printf("[deploy:%s] registry retention failed: %v", runID, err)
		return
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), registryRetentionLimit)
	defer cancel()

	docker := m.docker
	if docker == nil {
		docker = runDockerCommand
	}
	r := &registryRetentionRun{
		registry: &registryClient{baseURL: m.registryURLOrDefault(), http: &http.Client{Timeout: 30 * time.Second}},
		docker:   docker,
		logf: func(format string, args ...any) {
			m.logger.Printf("[deploy:%s] registry retention: "+format, append([]any{runID}, args...)...)
		},
	}
	summary, err := r.run(ctx, app.Name, app.RegistryKeepTags)
	if errors.Is(err, errRegistryDeleteDisabled) {
		m.logger.Printf("[deploy:%s] registry retention skipped: %v", runID, err)
		return
	}
	if err != nil {
		m.logger.Printf("[deploy:%s] registry retention failed after %dms: %v", runID, time.Since(start).Milliseconds(), err)
		return
	}
	m.logger.Printf("[deploy:%s] registry retention: %s duration_ms=%d", runID, summary, time.Since(start).Milliseconds())
}

func (m *DeployManager) registryURLOrDefault() string {
	if m.registryURL != "" {
		return m.registryURL
	}
	return registryBaseURL()
}

type registryRetentionRun struct {
	registry *registryClient
	docker   dockerCommandFunc
	logf     func(format string, args ...any)
}

func (r *registryRetentionRun) run(ctx context.Context, repo string, keepRecent int) (string, error) {
	if keepRecent < 1 {
		keepRecent = defaultRegistryKeepTags
	}
	tagNames, err := r.registry.tags(ctx, repo)
	if err != nil {
		return "", fmt.Errorf("list tags: %w", err)
	}
	if len(tagNames) == 0 {
		return "no tags in registry repo " + repo, nil
	}

	pinnedTags, pinnedDigests, err := containerImagePins(ctx, r.docker, repo, r.logf)
	if err != nil {
		// Without knowing what the containers run, deleting anything is unsafe.
		return "", fmt.Errorf("find container images: %w", err)
	}

	children := map[string][]string{}
	tags := make([]registryTag, 0, len(tagNames))
	for _, name := range tagNames {
		manifest, err := r.registry.manifest(ctx, repo, name)
		if err != nil {
			return "", fmt.Errorf("read manifest %s:%s: %w", repo, name, err)
		}
		children[manifest.Digest] = manifest.Children
		tag := registryTag{Name: name, Digest: manifest.Digest}
		// An unknown push time keeps the tag: it is never counted as old.
		if created, err := r.registry.created(ctx, repo, manifest); err == nil {
			tag.Created = created
		}
		tags = append(tags, tag)
	}
	for digest := range pinnedDigests {
		if _, ok := children[digest]; ok {
			continue
		}
		if manifest, err := r.registry.manifest(ctx, repo, digest); err == nil {
			children[digest] = manifest.Children
		}
	}

	plan := planRegistryRetention(tags, keepRecent, pinnedTags, pinnedDigests, children)
	if len(plan.Delete) == 0 {
		return fmt.Sprintf("tags=%d kept=%d deleted_manifests=0", len(tags), len(plan.KeepTags)), nil
	}

	deleted := 0
	var deleteErr error
	for _, digest := range plan.Delete {
		if err := r.registry.deleteManifest(ctx, repo, digest); err != nil {
			deleteErr = fmt.Errorf("delete %s@%s: %w", repo, digest, err)
			break
		}
		deleted++
	}
	if deleted == 0 {
		return "", deleteErr
	}

	reclaimed, gcErr := r.garbageCollect(ctx)
	summary := fmt.Sprintf("tags=%d kept=%d deleted_manifests=%d gc_blobs_deleted=%d", len(tags), len(plan.KeepTags), deleted, reclaimed)
	if err := errors.Join(deleteErr, gcErr); err != nil {
		return "", fmt.Errorf("%s: %w", summary, err)
	}
	return summary, nil
}

// garbageCollect runs a plain garbage-collect inside the registry container
// and then restarts it, so the registry drops its in-memory blob cache and
// cannot report deleted blobs as present to the next push. Pushes are blocked
// by the registry lock for the whole time, which is what read-only mode would
// give. The restart always runs, so the registry is never left down.
func (r *registryRetentionRun) garbageCollect(ctx context.Context) (deleted int, err error) {
	configPath := defaultRegistryConfig
	if out, inspectErr := r.docker(ctx, "inspect", "--format", "{{json .Config.Cmd}}", registryContainer); inspectErr == nil {
		configPath = registryConfigFromCmd(out)
	}

	defer func() {
		if restartErr := r.restartRegistry(); restartErr != nil {
			err = errors.Join(err, restartErr)
		}
	}()

	out, err := r.docker(ctx, "exec", registryContainer, "registry", "garbage-collect", configPath)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "eligible for deletion") {
			deleted++
		}
	}
	if err != nil {
		return deleted, fmt.Errorf("garbage-collect: %w: %s", err, lastLines(out, 5))
	}
	return deleted, nil
}

func (r *registryRetentionRun) restartRegistry() error {
	// Use a fresh context: the registry must come back even if the retention
	// context has run out.
	ctx, cancel := context.WithTimeout(context.Background(), 2*registryReadyTimeout)
	defer cancel()
	if out, err := r.docker(ctx, "restart", registryContainer); err != nil {
		r.logf("restart failed, starting instead: %v: %s", err, lastLines(out, 3))
		if out, err := r.docker(ctx, "start", registryContainer); err != nil {
			return fmt.Errorf("start registry: %w: %s", err, lastLines(out, 3))
		}
	}
	deadline := time.Now().Add(registryReadyTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = r.registry.ping(ctx); lastErr == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("registry not ready after restart: %w", lastErr)
}

func registryConfigFromCmd(out string) string {
	var cmd []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &cmd); err == nil {
		for i := len(cmd) - 1; i >= 0; i-- {
			if strings.HasSuffix(cmd[i], ".yml") || strings.HasSuffix(cmd[i], ".yaml") {
				return cmd[i]
			}
		}
	}
	return defaultRegistryConfig
}

func lastLines(out string, n int) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

type registryTag struct {
	Name    string
	Digest  string
	Created time.Time
}

type registryRetentionPlan struct {
	KeepTags    []string
	KeepDigests map[string]bool
	// Delete lists manifest digests to delete: the dropped tags' top-level
	// manifests first, then their children that no kept manifest references.
	Delete []string
}

// planRegistryRetention decides what to keep and delete. It keeps latest, the
// keepRecent newest tags, tags with an unknown or shared push time, and the tags and
// digests that containers use, plus every child of a kept manifest. It deletes
// the other tags' manifests and their children, except any digest it keeps:
// deleting a digest removes every tag on it.
func planRegistryRetention(tags []registryTag, keepRecent int, pinnedTags, pinnedDigests map[string]bool, children map[string][]string) registryRetentionPlan {
	ordered := append([]registryTag(nil), tags...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if !ordered[i].Created.Equal(ordered[j].Created) {
			return ordered[i].Created.After(ordered[j].Created)
		}
		return ordered[i].Name > ordered[j].Name
	})

	// Different images sharing a push time cannot be ordered against each
	// other (for example images built with a fixed SOURCE_DATE_EPOCH), so
	// they are kept. Tags on the same digest, like latest, are not ambiguous.
	digestsAtTime := map[time.Time]map[string]bool{}
	for _, tag := range ordered {
		if digestsAtTime[tag.Created] == nil {
			digestsAtTime[tag.Created] = map[string]bool{}
		}
		digestsAtTime[tag.Created][tag.Digest] = true
	}

	keepTag := map[string]bool{}
	recent := 0
	for _, tag := range ordered {
		switch {
		case tag.Name == "latest", pinnedTags[tag.Name], tag.Created.IsZero(), len(digestsAtTime[tag.Created]) > 1:
			keepTag[tag.Name] = true
		case recent < keepRecent:
			keepTag[tag.Name] = true
			recent++
		}
	}

	keepDigests := map[string]bool{}
	for digest := range pinnedDigests {
		keepDigests[digest] = true
	}
	for _, tag := range ordered {
		if keepTag[tag.Name] {
			keepDigests[tag.Digest] = true
		}
	}
	for digest := range keepDigests {
		for _, child := range children[digest] {
			keepDigests[child] = true
		}
	}

	plan := registryRetentionPlan{KeepDigests: keepDigests}
	queued := map[string]bool{}
	var childDeletes []string
	for _, tag := range ordered {
		if keepTag[tag.Name] || keepDigests[tag.Digest] {
			plan.KeepTags = append(plan.KeepTags, tag.Name)
			continue
		}
		if tag.Digest == "" || keepDigests[tag.Digest] || queued[tag.Digest] {
			continue
		}
		queued[tag.Digest] = true
		plan.Delete = append(plan.Delete, tag.Digest)
		for _, child := range children[tag.Digest] {
			if keepDigests[child] || queued[child] {
				continue
			}
			queued[child] = true
			childDeletes = append(childDeletes, child)
		}
	}
	plan.Delete = append(plan.Delete, childDeletes...)
	return plan
}

// containerImagePins returns the registry tags and digests used by the app's
// running containers and its newest stopped container. A container whose image
// is no longer in the local store (removed by an image prune) is pinned only by
// the tag or digest in its own image reference; any other inspect error fails.
func containerImagePins(ctx context.Context, docker dockerCommandFunc, repo string, logf func(format string, args ...any)) (map[string]bool, map[string]bool, error) {
	out, err := docker(ctx, "ps", "-a", "--filter", "label=service="+repo, "--format", "{{.State}}\t{{.Image}}")
	if err != nil {
		return nil, nil, fmt.Errorf("docker ps: %w: %s", err, lastLines(out, 3))
	}
	var images []string
	stoppedSeen := false
	// docker ps lists the newest container first.
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		state, image, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || image == "" {
			continue
		}
		if state != "running" {
			if stoppedSeen {
				continue
			}
			stoppedSeen = true
		}
		images = append(images, image)
	}

	tags := map[string]bool{}
	digests := map[string]bool{}
	for _, image := range images {
		if tag, digest := imageRefTagOrDigest(image, repo); tag != "" {
			tags[tag] = true
		} else if digest != "" {
			digests[digest] = true
		}
		out, err := docker(ctx, "image", "inspect", "--format", "{{range .RepoDigests}}{{println .}}{{end}}", image)
		if err != nil {
			if isNoSuchImage(out) {
				if logf != nil {
					logf("warning: image %s of a container is gone locally; pinning only its own reference", image)
				}
				continue
			}
			return nil, nil, fmt.Errorf("docker image inspect %s: %w: %s", image, err, lastLines(out, 3))
		}
		for _, ref := range strings.Fields(out) {
			if _, digest := imageRefTagOrDigest(ref, repo); digest != "" {
				digests[digest] = true
			}
		}
	}
	return tags, digests, nil
}

// isNoSuchImage reports whether docker output says the image is not in the
// local image store.
func isNoSuchImage(out string) bool {
	return strings.Contains(strings.ToLower(out), "no such image")
}

// imageRefTagOrDigest parses an image reference such as
// 127.0.0.1:5555/app:abc or 127.0.0.1:5555/app@sha256:... and returns its tag
// or digest when it names the given registry repository.
func imageRefTagOrDigest(ref, repo string) (tag, digest string) {
	name, dgst, hasDigest := strings.Cut(ref, "@")
	tagged := ""
	if slash := strings.LastIndex(name, "/"); strings.LastIndex(name, ":") > slash {
		colon := strings.LastIndex(name, ":")
		name, tagged = name[:colon], name[colon+1:]
	}
	path := name
	if slash := strings.Index(name, "/"); slash >= 0 && strings.ContainsAny(name[:slash], ".:") {
		path = name[slash+1:]
	}
	if path != repo {
		return "", ""
	}
	if hasDigest {
		return "", dgst
	}
	return tagged, ""
}

type registryClient struct {
	baseURL string
	http    *http.Client
}

type registryManifest struct {
	Digest    string
	MediaType string
	Config    string
	Children  []string
	// timeChild is the platform manifest whose config gives the push time.
	timeChild string
}

var manifestAccept = strings.Join([]string{mediaTypeOCIIndex, mediaTypeDockerList, mediaTypeOCIManifest, mediaTypeDockerManifest}, ", ")

func (c *registryClient) do(ctx context.Context, method, path string, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return c.http.Do(req)
}

var linkNextPattern = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func (c *registryClient) tags(ctx context.Context, repo string) ([]string, error) {
	var all []string
	next := "/v2/" + repo + "/tags/list?n=1000"
	for next != "" {
		res, err := c.do(ctx, http.MethodGet, next, "")
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return nil, err
		}
		if res.StatusCode == http.StatusNotFound {
			return all, nil
		}
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("tags list returned %s", res.Status)
		}
		var page struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Tags...)
		next = ""
		if match := linkNextPattern.FindStringSubmatch(res.Header.Get("Link")); len(match) == 2 {
			if parsed, err := url.Parse(match[1]); err == nil {
				next = parsed.RequestURI()
			}
		}
	}
	return all, nil
}

func (c *registryClient) manifest(ctx context.Context, repo, ref string) (registryManifest, error) {
	res, err := c.do(ctx, http.MethodGet, "/v2/"+repo+"/manifests/"+ref, manifestAccept)
	if err != nil {
		return registryManifest{}, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return registryManifest{}, err
	}
	if res.StatusCode != http.StatusOK {
		return registryManifest{}, fmt.Errorf("manifest %s returned %s", ref, res.Status)
	}
	var raw struct {
		MediaType string `json:"mediaType"`
		Config    struct {
			Digest string `json:"digest"`
		} `json:"config"`
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform *struct {
				OS string `json:"os"`
			} `json:"platform"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return registryManifest{}, err
	}
	m := registryManifest{
		Digest:    res.Header.Get("Docker-Content-Digest"),
		MediaType: raw.MediaType,
		Config:    raw.Config.Digest,
	}
	if m.MediaType == "" {
		m.MediaType = strings.TrimSpace(strings.Split(res.Header.Get("Content-Type"), ";")[0])
	}
	if m.Digest == "" {
		sum := sha256.Sum256(body)
		m.Digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	for _, child := range raw.Manifests {
		m.Children = append(m.Children, child.Digest)
		attestation := child.Annotations["vnd.docker.reference.type"] == "attestation-manifest" ||
			(child.Platform != nil && child.Platform.OS == "unknown")
		if m.timeChild == "" && !attestation {
			m.timeChild = child.Digest
		}
	}
	return m, nil
}

// created returns the image's creation time from its config blob, which for
// buildx images is the build (and so push) time.
func (c *registryClient) created(ctx context.Context, repo string, m registryManifest) (time.Time, error) {
	if m.Config == "" {
		if m.timeChild == "" {
			return time.Time{}, errors.New("no platform manifest")
		}
		child, err := c.manifest(ctx, repo, m.timeChild)
		if err != nil {
			return time.Time{}, err
		}
		m = child
	}
	if m.Config == "" {
		return time.Time{}, errors.New("no image config")
	}
	res, err := c.do(ctx, http.MethodGet, "/v2/"+repo+"/blobs/"+m.Config, "")
	if err != nil {
		return time.Time{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("config blob returned %s", res.Status)
	}
	var config struct {
		Created time.Time `json:"created"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(&config); err != nil {
		return time.Time{}, err
	}
	return config.Created, nil
}

func (c *registryClient) deleteManifest(ctx context.Context, repo, digest string) error {
	if !strings.HasPrefix(digest, "sha256:") {
		return fmt.Errorf("refusing to delete non-digest reference %q", digest)
	}
	res, err := c.do(ctx, http.MethodDelete, "/v2/"+repo+"/manifests/"+digest, "")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	switch {
	case res.StatusCode == http.StatusAccepted, res.StatusCode == http.StatusOK, res.StatusCode == http.StatusNotFound:
		return nil
	case res.StatusCode == http.StatusMethodNotAllowed:
		return errRegistryDeleteDisabled
	default:
		return fmt.Errorf("delete returned %s", res.Status)
	}
}

func (c *registryClient) ping(ctx context.Context) error {
	res, err := c.do(ctx, http.MethodGet, "/v2/", "")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("/v2/ returned %s", res.Status)
	}
	return nil
}
