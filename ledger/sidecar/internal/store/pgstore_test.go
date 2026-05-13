package store

import (
	"io/fs"
	"testing"
)

func TestIsMigrationFileSkipsAppleDoubleFiles(t *testing.T) {
	entries := []struct {
		name string
		mode fs.FileMode
		want bool
	}{
		{name: "0001_init.sql", want: true},
		{name: "._0001_init.sql", want: false},
		{name: ".DS_Store", want: false},
		{name: "notes.txt", want: false},
		{name: "migrations", mode: fs.ModeDir, want: false},
	}
	for _, tc := range entries {
		t.Run(tc.name, func(t *testing.T) {
			got := isMigrationFile(fakeDirEntry{name: tc.name, mode: tc.mode})
			if got != tc.want {
				t.Fatalf("isMigrationFile(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

type fakeDirEntry struct {
	name string
	mode fs.FileMode
}

func (e fakeDirEntry) Name() string               { return e.name }
func (e fakeDirEntry) IsDir() bool                { return e.mode.IsDir() }
func (e fakeDirEntry) Type() fs.FileMode          { return e.mode.Type() }
func (e fakeDirEntry) Info() (fs.FileInfo, error) { return nil, nil }
