package lru

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Settings_SetDefaults(t *testing.T) {
	settings := Settings{}
	settings.SetDefaults()

	assert.Greater(t, settings.MaxEntries, 1)
}
