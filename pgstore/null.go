package pgstore

import (
	"database/sql"
	"time"
)

// NULL is an answer here ("never used", "no org yet"); a zero time or "" would
// become year 1 or an org id of "".

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func timePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// nullString: "" is absent, since every column using it is a foreign key.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
