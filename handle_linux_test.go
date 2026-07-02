package netlink

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSetGetSocketTimeout(t *testing.T) {
	timeout := 10 * time.Second
	if err := SetSocketTimeout(10 * time.Second); err != nil {
		t.Fatalf("Set socket timeout for default handle failed: %v", err)
	}

	if val := GetSocketTimeout(); val != timeout {
		t.Fatalf("Unexpected socket timeout value: got=%v, expected=%v", val, timeout)
	}
}

func TestConfigureHandle(t *testing.T) {
	t.Cleanup(func() {
		pkgOptions = HandleOptions{}
		oncePkgOptions = sync.Once{}
	})

	assert.NoError(t, ConfigureHandle(HandleOptions{DisableVFInfoCollection: true}))
	assert.True(t, pkgOptions.DisableVFInfoCollection)

	assert.Error(t, ConfigureHandle(HandleOptions{}))
}
