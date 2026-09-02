package authz_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ArmornetIO/identity/authz"
)

const testMappingYAML = `
version: 1
claim: groups
mappings:
  - pattern: "armornet:org:(?P<org_id>[^:]+):owner"
    tuples:
      - relation: owner
        object: "organization:{org_id}"
  - pattern: "armornet:org:(?P<org_id>[^:]+):admin"
    tuples:
      - relation: admin
        object: "organization:{org_id}"
  - pattern: "armornet:org:(?P<org_id>[^:]+):member"
    tuples:
      - relation: member
        object: "organization:{org_id}"
`

func TestClaimMapper_ParsesYAML(t *testing.T) {
	t.Parallel()
	m, err := authz.ParseMapper([]byte(testMappingYAML))
	require.NoError(t, err)
	assert.NotNil(t, m)
}

func TestClaimMapper_InvalidYAMLReturnsError(t *testing.T) {
	t.Parallel()
	_, err := authz.ParseMapper([]byte(":::invalid:::"))
	require.Error(t, err)
}

// Well-formed YAML with no version is rejected, not loaded silently.
func TestClaimMapper_MissingVersionReturnsError(t *testing.T) {
	t.Parallel()
	_, err := authz.ParseMapper([]byte("claim: groups\nmappings: []\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version")
}

// A bad regex fails at startup, not by silently dropping the mapping later.
func TestClaimMapper_UncompilablePatternReturnsError(t *testing.T) {
	t.Parallel()
	const badPattern = `
version: 1
claim: groups
mappings:
  - pattern: "armornet:org:(?P<org_id>[^:+):admin"
    tuples:
      - relation: admin
        object: "organization:{org_id}"
`
	_, err := authz.ParseMapper([]byte(badPattern))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compile pattern")
}

// TestLoadMapper_MissingFileReturnsError covers the file-read failure path of
// LoadMapper (a misconfigured mapper path at deploy time).
func TestLoadMapper_MissingFileReturnsError(t *testing.T) {
	t.Parallel()
	_, err := authz.LoadMapper(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	require.Error(t, err)
}

// An unmatched {placeholder} is rejected at load, or "organization:{org_id}"
// leaks into checks and silently matches nothing.
func TestClaimMapper_UndefinedPlaceholderRejectedAtParse(t *testing.T) {
	t.Parallel()
	const noCapture = `
version: 1
claim: groups
mappings:
  - pattern: "armornet:staff"
    tuples:
      - relation: admin
        object: "organization:{org_id}"
`
	_, err := authz.ParseMapper([]byte(noCapture))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "org_id")
}

// The common typo: the pattern defines {org_id}, the tuple says {org}.
func TestClaimMapper_MisspelledPlaceholderRejectedAtParse(t *testing.T) {
	t.Parallel()
	const typo = `
version: 1
claim: groups
mappings:
  - pattern: "armornet:org:(?P<org_id>[^:]+):admin"
    tuples:
      - relation: admin
        object: "organization:{org}"
`
	_, err := authz.ParseMapper([]byte(typo))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "org")
}

func TestClaimMapper_OrgAdminGroupProducesAdminTuple(t *testing.T) {
	t.Parallel()
	m, err := authz.ParseMapper([]byte(testMappingYAML))
	require.NoError(t, err)

	tuples := m.TuplesForGroups("user:alice", []string{"armornet:org:acme:admin"})
	require.Len(t, tuples, 1)
	assert.Equal(t, "user:alice", tuples[0].User)
	assert.Equal(t, "admin", tuples[0].Relation)
	assert.Equal(t, "organization:acme", tuples[0].Object)
}

func TestClaimMapper_OrgMemberGroupProducesMemberTuple(t *testing.T) {
	t.Parallel()
	m, err := authz.ParseMapper([]byte(testMappingYAML))
	require.NoError(t, err)

	tuples := m.TuplesForGroups("user:bob", []string{"armornet:org:beta:member"})
	require.Len(t, tuples, 1)
	assert.Equal(t, "user:bob", tuples[0].User)
	assert.Equal(t, "member", tuples[0].Relation)
	assert.Equal(t, "organization:beta", tuples[0].Object)
}

func TestClaimMapper_OrgOwnerGroupProducesOwnerTuple(t *testing.T) {
	t.Parallel()
	m, err := authz.ParseMapper([]byte(testMappingYAML))
	require.NoError(t, err)

	tuples := m.TuplesForGroups("user:owner", []string{"armornet:org:gamma:owner"})
	require.Len(t, tuples, 1)
	assert.Equal(t, "owner", tuples[0].Relation)
	assert.Equal(t, "organization:gamma", tuples[0].Object)
}

func TestClaimMapper_UnknownGroupPatternIsIgnored(t *testing.T) {
	t.Parallel()
	m, err := authz.ParseMapper([]byte(testMappingYAML))
	require.NoError(t, err)

	tuples := m.TuplesForGroups("user:x", []string{"some-other:group:value"})
	assert.Empty(t, tuples)
}

func TestClaimMapper_MultipleGroupsProduceMultipleTuples(t *testing.T) {
	t.Parallel()
	m, err := authz.ParseMapper([]byte(testMappingYAML))
	require.NoError(t, err)

	tuples := m.TuplesForGroups("user:multi", []string{
		"armornet:org:acme:admin",
		"armornet:org:beta:member",
	})
	require.Len(t, tuples, 2)
}

func TestClaimMapper_EmptyGroupsReturnsEmptyTuples(t *testing.T) {
	t.Parallel()
	m, err := authz.ParseMapper([]byte(testMappingYAML))
	require.NoError(t, err)

	tuples := m.TuplesForGroups("user:nobody", nil)
	assert.Empty(t, tuples)
}

func TestClaimMapper_OrgIDExtractedFromPattern(t *testing.T) {
	t.Parallel()
	m, err := authz.ParseMapper([]byte(testMappingYAML))
	require.NoError(t, err)

	tuples := m.TuplesForGroups("user:x", []string{"armornet:org:my-company-inc:admin"})
	require.Len(t, tuples, 1)
	assert.Equal(t, "organization:my-company-inc", tuples[0].Object)
}
