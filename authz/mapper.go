package authz

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ContextualTuple is built from IdP group claims per check, never written to FGA.
type ContextualTuple struct {
	User     string
	Relation string
	Object   string
}

// mapperConfig is the on-disk YAML schema for claim→tuple mappings.
type mapperConfig struct {
	Version  int            `yaml:"version"`
	Claim    string         `yaml:"claim"`
	Mappings []mappingEntry `yaml:"mappings"`
}

type mappingEntry struct {
	Pattern string      `yaml:"pattern"`
	Tuples  []tupleSpec `yaml:"tuples"`
}

type tupleSpec struct {
	Relation string `yaml:"relation"`
	Object   string `yaml:"object"`
}

// compiledMapping holds a compiled pattern alongside its tuple templates.
type compiledMapping struct {
	re     *regexp.Regexp
	tuples []tupleSpec
}

// ClaimMapper translates IDP group claims into OpenFGA contextual tuples.
// Loaded once at startup via ParseMapper or LoadMapper.
type ClaimMapper struct {
	mappings []compiledMapping
}

// LoadMapper reads a YAML mapping config from path and compiles all patterns.
func LoadMapper(path string) (*ClaimMapper, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator's mapping config, loaded once at startup
	if err != nil {
		return nil, fmt.Errorf("authz: load mapper %q: %w", path, err)
	}
	return ParseMapper(data)
}

// ParseMapper parses YAML config bytes and compiles all patterns.
func ParseMapper(data []byte) (*ClaimMapper, error) {
	var cfg mapperConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("authz: parse mapper config: %w", err)
	}
	if cfg.Version == 0 {
		return nil, fmt.Errorf("authz: mapper config missing version field")
	}

	cm := &ClaimMapper{}
	for _, m := range cfg.Mappings {
		re, err := regexp.Compile(m.Pattern)
		if err != nil {
			return nil, fmt.Errorf("authz: compile pattern %q: %w", m.Pattern, err)
		}
		if err := validatePlaceholders(re, m.Tuples); err != nil {
			return nil, fmt.Errorf("authz: pattern %q: %w", m.Pattern, err)
		}
		cm.mappings = append(cm.mappings, compiledMapping{re: re, tuples: m.Tuples})
	}
	return cm, nil
}

// placeholderRE matches "{name}" template placeholders in a tuple object spec.
var placeholderRE = regexp.MustCompile(`\{([^}]+)\}`)

// validatePlaceholders fails at load on a placeholder with no capture group;
// expandTemplate would leave it verbatim, a tuple that silently matches nothing.
func validatePlaceholders(re *regexp.Regexp, tuples []tupleSpec) error {
	groups := make(map[string]struct{})
	for _, name := range re.SubexpNames() {
		if name != "" {
			groups[name] = struct{}{}
		}
	}
	for _, spec := range tuples {
		for _, m := range placeholderRE.FindAllStringSubmatch(spec.Object, -1) {
			name := m[1]
			if _, ok := groups[name]; !ok {
				return fmt.Errorf("object %q references undefined capture group {%s}", spec.Object, name)
			}
		}
	}
	return nil
}

// TuplesForGroups maps a slice of IDP group strings into contextual tuples for
// the given subject. Groups that match no pattern are silently ignored.
func (m *ClaimMapper) TuplesForGroups(subject string, groups []string) []ContextualTuple {
	var out []ContextualTuple
	for _, group := range groups {
		for _, cm := range m.mappings {
			match := cm.re.FindStringSubmatch(group)
			if match == nil {
				continue
			}
			captures := namedCaptures(cm.re, match)
			for _, spec := range cm.tuples {
				out = append(out, ContextualTuple{
					User:     subject,
					Relation: spec.Relation,
					Object:   expandTemplate(spec.Object, captures),
				})
			}
		}
	}
	return out
}

// namedCaptures returns a map of named capture groups from a regex match.
func namedCaptures(re *regexp.Regexp, match []string) map[string]string {
	caps := make(map[string]string, len(re.SubexpNames()))
	for i, name := range re.SubexpNames() {
		if name != "" && i < len(match) {
			caps[name] = match[i]
		}
	}
	return caps
}

// expandTemplate replaces {key} placeholders with values from captures.
func expandTemplate(tmpl string, captures map[string]string) string {
	for k, v := range captures {
		tmpl = strings.ReplaceAll(tmpl, "{"+k+"}", v)
	}
	return tmpl
}
