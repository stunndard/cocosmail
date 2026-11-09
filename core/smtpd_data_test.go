package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnstuffDot(t *testing.T) {
	assert.Equal(t, ".\r\n", string(unstuffDot([]byte("..\r\n"))))
	assert.Equal(t, ".jpg\" style\r\n", string(unstuffDot([]byte("..jpg\" style\r\n"))))
	assert.Equal(t, "\r\n", string(unstuffDot([]byte(".\r\n"))))
	assert.Equal(t, "a.b\r\n", string(unstuffDot([]byte("a.b\r\n"))))
	assert.Equal(t, "\r\n", string(unstuffDot([]byte("\r\n"))))
}
