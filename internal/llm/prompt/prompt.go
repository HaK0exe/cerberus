// Package prompt loads and renders versioned LLM prompt templates from
// prompts/*.md. Each template carries an explicit version identifier in
// its front matter; that version is threaded into
// llm.CacheKeyInput.PromptVersion (see internal/llm/validator.go and
// docs/architecture/llm-non-sovereign.md) so a response cache entry is
// never reused across prompt wording changes.
//
// Templates never see a raw secret value: they are rendered against
// cerberus.ValidationInput, whose RedactedContext field has already had
// secret material stripped by llm.Sanitize before it ever reaches this
// package.
package prompt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"

	"github.com/HaK0exe/cerberus/pkg/cerberus"
)

// frontMatterDelim delimits the YAML-ish front matter block at the top
// of a template file from its body.
const frontMatterDelim = "---"

// Template is a single loaded, parsed prompt template.
type Template struct {
	// ID identifies the template independent of its version (e.g.
	// "candidate_validation"). Multiple versions of the same ID may be
	// loaded at once.
	ID string
	// Version is the explicit, monotonically increasing version of this
	// template's wording. Bump it whenever the Body text changes.
	Version int
	// Description is an optional human-readable summary from the front
	// matter.
	Description string
	// Body is the raw template text (Go text/template syntax) after the
	// front matter block has been stripped.
	Body string
	// Path is the source file path this template was loaded from,
	// relative to the fs.FS root it was loaded with. Used for error
	// messages only.
	Path string

	tmpl *template.Template
}

// VersionString returns the template's version as the string form used
// in cache keys and logs (e.g. llm.CacheKeyInput.PromptVersion).
func (t Template) VersionString() string {
	return fmt.Sprintf("%s@%d", t.ID, t.Version)
}

// Checksum returns the hex-encoded SHA-256 of the template's rendered
// body text (post front matter). It is used to pin each (ID, Version)
// pair to its exact wording — see the checksum lock test in
// prompt_lock_test.go, which fails if a template's wording changes
// without a matching version bump.
func (t Template) Checksum() string {
	sum := sha256.Sum256([]byte(t.Body))
	return hex.EncodeToString(sum[:])
}

// Render executes the template against a ValidationInput. The input's
// RedactedContext must already be sanitized (see llm.Sanitize) — this
// function performs no redaction itself.
func (t Template) Render(input cerberus.ValidationInput) (string, error) {
	if t.tmpl == nil {
		return "", fmt.Errorf("prompt: template %s is not parsed (zero value or loaded incorrectly)", t.VersionString())
	}
	var buf bytes.Buffer
	if err := t.tmpl.Execute(&buf, input); err != nil {
		return "", fmt.Errorf("prompt: rendering %s: %w", t.VersionString(), err)
	}
	return buf.String(), nil
}

// Store holds every loaded template, keyed by ID and Version, so callers
// can pin a specific version (e.g. to reproduce a cached response) or
// fetch the latest.
type Store struct {
	// byID maps template ID -> version -> Template.
	byID map[string]map[int]*Template
}

// NewStore returns an empty Store. Use LoadDir to populate one from
// disk.
func NewStore() *Store {
	return &Store{byID: make(map[string]map[int]*Template)}
}

// LoadDir walks dir (within fsys) and loads every *.md file as a
// versioned prompt template. It returns an error if any file is
// malformed, or if the same (ID, Version) pair appears more than once.
func LoadDir(fsys fs.FS, dir string) (*Store, error) {
	s := NewStore()

	err := fs.WalkDir(fsys, dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) != ".md" {
			return nil
		}

		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("prompt: reading %s: %w", path, err)
		}

		tmpl, err := parse(path, raw)
		if err != nil {
			return err
		}

		if err := s.add(tmpl); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) add(t *Template) error {
	versions, ok := s.byID[t.ID]
	if !ok {
		versions = make(map[int]*Template)
		s.byID[t.ID] = versions
	}
	if existing, ok := versions[t.Version]; ok {
		return fmt.Errorf("prompt: duplicate template %s (%s and %s)", t.VersionString(), existing.Path, t.Path)
	}
	versions[t.Version] = t
	return nil
}

// Get returns the highest-versioned template for id.
func (s *Store) Get(id string) (Template, error) {
	versions, ok := s.byID[id]
	if !ok || len(versions) == 0 {
		return Template{}, fmt.Errorf("prompt: no template with id %q", id)
	}
	var latest int
	for v := range versions {
		if v > latest {
			latest = v
		}
	}
	return *versions[latest], nil
}

// GetVersion returns a specific version of template id. Returns an
// error if that exact version is not loaded.
func (s *Store) GetVersion(id string, version int) (Template, error) {
	versions, ok := s.byID[id]
	if !ok {
		return Template{}, fmt.Errorf("prompt: no template with id %q", id)
	}
	t, ok := versions[version]
	if !ok {
		return Template{}, fmt.Errorf("prompt: no version %d of template %q", version, id)
	}
	return *t, nil
}

// IDs returns every distinct template ID loaded, sorted.
func (s *Store) IDs() []string {
	ids := make([]string, 0, len(s.byID))
	for id := range s.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// parse splits raw file content into front matter + body, validates the
// front matter, and compiles the body as a text/template.
func parse(path string, raw []byte) (*Template, error) {
	content := string(raw)

	fm, body, err := splitFrontMatter(content)
	if err != nil {
		return nil, fmt.Errorf("prompt: %s: %w", path, err)
	}

	fmData, err := parseFrontMatter(fm)
	if err != nil {
		return nil, fmt.Errorf("prompt: %s: %w", path, err)
	}
	id, version, description := fmData.ID, fmData.Version, fmData.Description

	body = strings.TrimLeft(body, "\n")
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("prompt: %s: empty template body", path)
	}

	parsed, err := template.New(path).Option("missingkey=error").Parse(body)
	if err != nil {
		return nil, fmt.Errorf("prompt: %s: parsing body as template: %w", path, err)
	}

	return &Template{
		ID:          id,
		Version:     version,
		Description: description,
		Body:        body,
		Path:        path,
		tmpl:        parsed,
	}, nil
}

// splitFrontMatter separates a leading "---\n...\n---\n" block from the
// rest of the file.
func splitFrontMatter(content string) (frontMatter string, body string, err error) {
	if !strings.HasPrefix(content, frontMatterDelim) {
		return "", "", fmt.Errorf("missing front matter (file must start with %q)", frontMatterDelim)
	}
	rest := content[len(frontMatterDelim):]
	rest = strings.TrimPrefix(rest, "\n")

	end := strings.Index(rest, "\n"+frontMatterDelim)
	if end == -1 {
		return "", "", fmt.Errorf("unterminated front matter (missing closing %q)", frontMatterDelim)
	}
	frontMatter = rest[:end]
	body = rest[end+len("\n"+frontMatterDelim):]
	return frontMatter, body, nil
}

// frontMatter is the strict schema for a template's YAML front matter
// block. yaml.v3's KnownFields(true) rejects any field not listed here,
// so a typo'd key fails loudly instead of being silently ignored.
type frontMatter struct {
	ID          string `yaml:"id"`
	Version     int    `yaml:"version"`
	Description string `yaml:"description"`
}

// parseFrontMatter decodes and validates a template's front matter
// block.
func parseFrontMatter(fm string) (frontMatter, error) {
	var out frontMatter

	dec := yaml.NewDecoder(strings.NewReader(fm))
	dec.KnownFields(true)
	if err := dec.Decode(&out); err != nil {
		return frontMatter{}, fmt.Errorf("parsing front matter: %w", err)
	}

	if out.ID == "" {
		return frontMatter{}, fmt.Errorf("front matter missing required field \"id\"")
	}
	if out.Version < 1 {
		return frontMatter{}, fmt.Errorf("front matter missing required field \"version\" (must be >= 1)")
	}
	return out, nil
}
