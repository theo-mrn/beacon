package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS endpoints (
	key         TEXT PRIMARY KEY,
	fingerprint TEXT NOT NULL,
	first_seen  DATETIME NOT NULL,
	last_seen   DATETIME NOT NULL
);`

// Status indique si un endpoint est nouveau, modifié, ou connu.
type Status string

const (
	StatusNew      Status = "NEW"
	StatusModified Status = "MODIFIED"
	StatusKnown    Status = "KNOWN"
)

// Record est ce que le store conserve pour chaque endpoint.
type Record struct {
	Key         string
	Fingerprint string
	FirstSeen   time.Time
	LastSeen    time.Time
}

type Store struct {
	db *sql.DB
}

// Open ouvre (ou crée) la base SQLite au chemin donné.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() { s.db.Close() }

// Observe enregistre un endpoint et retourne son statut (NEW / MODIFIED / KNOWN).
// fingerprint est un hash des propriétés de l'endpoint (ports, destination, type).
func (s *Store) Observe(key, fingerprint string) (Status, Record, error) {
	now := time.Now().UTC()

	var rec Record
	err := s.db.QueryRow(
		`SELECT key, fingerprint, first_seen, last_seen FROM endpoints WHERE key = ?`, key,
	).Scan(&rec.Key, &rec.Fingerprint, &rec.FirstSeen, &rec.LastSeen)

	if err == sql.ErrNoRows {
		// Nouveau
		_, err = s.db.Exec(
			`INSERT INTO endpoints (key, fingerprint, first_seen, last_seen) VALUES (?, ?, ?, ?)`,
			key, fingerprint, now, now,
		)
		return StatusNew, Record{Key: key, Fingerprint: fingerprint, FirstSeen: now, LastSeen: now}, err
	}
	if err != nil {
		return StatusKnown, rec, err
	}

	// Mise à jour last_seen systématiquement
	_, err = s.db.Exec(`UPDATE endpoints SET last_seen = ? WHERE key = ?`, now, key)
	if err != nil {
		return StatusKnown, rec, err
	}
	rec.LastSeen = now

	if rec.Fingerprint != fingerprint {
		// Modifié
		_, err = s.db.Exec(`UPDATE endpoints SET fingerprint = ? WHERE key = ?`, fingerprint, key)
		rec.Fingerprint = fingerprint
		return StatusModified, rec, err
	}

	return StatusKnown, rec, nil
}

// Fingerprint construit une empreinte stable pour un endpoint à partir de ses propriétés clés.
func Fingerprint(sourceKind, externalIP, hostname string, ports []int32) string {
	data := map[string]interface{}{
		"kind":     sourceKind,
		"ip":       externalIP,
		"hostname": hostname,
		"ports":    ports,
	}
	b, _ := json.Marshal(data)
	return string(b)
}

// Cleanup supprime les entrées non vues depuis plus de `age`.
func (s *Store) Cleanup(age time.Duration) error {
	cutoff := time.Now().UTC().Add(-age)
	_, err := s.db.Exec(`DELETE FROM endpoints WHERE last_seen < ?`, cutoff)
	return err
}
