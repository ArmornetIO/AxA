package dex

import (
	"testing"
	"time"
)

func TestNew_MissingIssuerURL(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("expected error for empty IssuerURL, got nil")
	}
}

func TestNew_DefaultsApplied(t *testing.T) {
	srv, err := New(Config{IssuerURL: "https://api.example.com/dex"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.cfg.RotateKeysAfter != 6*time.Hour {
		t.Errorf("RotateKeysAfter = %v, want 6h", srv.cfg.RotateKeysAfter)
	}
	if srv.cfg.IDTokensValidFor != 24*time.Hour {
		t.Errorf("IDTokensValidFor = %v, want 24h", srv.cfg.IDTokensValidFor)
	}
}

func TestNew_ExplicitDurationsPreserved(t *testing.T) {
	srv, err := New(Config{
		IssuerURL:        "https://api.example.com/dex",
		RotateKeysAfter:  12 * time.Hour,
		IDTokensValidFor: 48 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.cfg.RotateKeysAfter != 12*time.Hour {
		t.Errorf("RotateKeysAfter = %v, want 12h", srv.cfg.RotateKeysAfter)
	}
	if srv.cfg.IDTokensValidFor != 48*time.Hour {
		t.Errorf("IDTokensValidFor = %v, want 48h", srv.cfg.IDTokensValidFor)
	}
}

func TestNew_TokenTTLShorterThanRotation_Rejected(t *testing.T) {
	_, err := New(Config{
		IssuerURL:        "https://api.example.com/dex",
		RotateKeysAfter:  24 * time.Hour,
		IDTokensValidFor: 1 * time.Hour,
	})
	if err == nil {
		t.Fatal("expected error when IDTokensValidFor < RotateKeysAfter")
	}
}

func TestNew_BrokerNonNilBeforeStart(t *testing.T) {
	srv, err := New(Config{IssuerURL: "https://api.example.com/dex"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.Broker() == nil {
		t.Error("Broker() should be non-nil immediately after New()")
	}
}
