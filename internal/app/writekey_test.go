package app

import (
	"testing"

	"github.com/yarrasatwik/gatecrasher/internal/config"
	"github.com/yarrasatwik/gatecrasher/internal/flagsmith"
)

const (
	testOrgKey   = "orgkey01.abcdefghijklmnopqrstuvwxyz012345"
	testWriteKey = "writekey.abcdefghijklmnopqrstuvwxyz012345"
)

func TestWritesUseTheWriteKeyWhenSet(t *testing.T) {
	org := flagsmith.NewAdmin(nil, "http://localhost:8000/api/v1/", testOrgKey)
	a := &App{Cfg: &config.Config{OrgAPIKey: testOrgKey, WriteAPIKey: testWriteKey}, Admin: org}
	a.Cfg.Flagsmith.APIURL = "http://localhost:8000/api/v1/"
	if a.writeAdmin() == org {
		t.Fatal("writes must not use the read (org) key when a write key is set")
	}
	if !a.KeysSplit() {
		t.Fatal("KeysSplit = false with a write key set")
	}
	if a.writeCLIKey() != testWriteKey {
		t.Fatal("the Flagsmith CLI must get the write key")
	}
}

func TestWritesFallBackToTheOrgKey(t *testing.T) {
	org := flagsmith.NewAdmin(nil, "http://localhost:8000/api/v1/", testOrgKey)
	a := &App{Cfg: &config.Config{OrgAPIKey: testOrgKey}, Admin: org}
	if a.writeAdmin() != org {
		t.Fatal("without a write key, writes must fall back to the org key")
	}
	if a.KeysSplit() {
		t.Fatal("KeysSplit = true without a write key")
	}
	if a.writeCLIKey() != testOrgKey {
		t.Fatal("the Flagsmith CLI must fall back to the org key")
	}
}
