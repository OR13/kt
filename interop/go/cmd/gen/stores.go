package main

import (
	"context"

	"github.com/Bren2010/katie/db"
)

// In-memory stores. katie folded db/memory into db and replaced the three
// separate stores with views over one TransparencyStore, so every tree in a
// generator gets its own key-value store here.

func newTransparencyStore() db.TransparencyStore {
	return db.NewTransparencyStore(context.Background(), db.NewMemoryKeyValueStore(), false)
}

func newLogStore() db.LogStore { return newTransparencyStore().LogStore() }

func newPrefixStore() db.PrefixStore { return newTransparencyStore().PrefixStore() }
