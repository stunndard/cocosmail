package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatVersion(t *testing.T) {
	assert.Equal(t, "0.3.0 (commit ab69894, 2026-11-09)", formatVersion("0.3.0", "ab69894c0ffee1234567890abcdef1234567890a", "2026-11-09T07:10:00Z", false))
	assert.Equal(t, "0.3.0 (commit ab69894, 2026-11-09, modified)", formatVersion("0.3.0", "ab69894c0ffee", "2026-11-09T07:10:00Z", true))
	assert.Equal(t, "0.3.0 (commit ab69894)", formatVersion("0.3.0", "ab69894", "", false))
	assert.Equal(t, "0.3.0 (commit unknown)", formatVersion("0.3.0", "", "", false))
}
