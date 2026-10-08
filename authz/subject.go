package authz

import (
	"errors"
	"strings"
)

// ErrNotRepresentable is an authorization answer: map it to a refusal, never an outage.
var ErrNotRepresentable = errors.New("authz: subject not representable")

// Subject's graph type arrives already decided by the composer and the model.
type Subject struct {
	Type string
	ID   string
}

// Valid refuses ':' in an id: the graph splits on it, which is how
// "agent:<org>:<uuid>" once surfaced as an outage instead of a deny.
func (s Subject) Valid() error {
	if s.Type == "" || s.ID == "" || strings.Contains(s.ID, ":") {
		return ErrNotRepresentable
	}
	return nil
}

// Graph is the only place "type:id" is assembled; a hand-built "user:"+id is
// how a machine got checked as a person.
func (s Subject) Graph() (string, error) {
	if err := s.Valid(); err != nil {
		return "", err
	}
	return s.Type + ":" + s.ID, nil
}
