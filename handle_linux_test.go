package netlink

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
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
	orig := pkgHandle
	origDone := configDone
	t.Cleanup(func() {
		configMu.Lock()
		defer configMu.Unlock()

		pkgHandle = orig
		configDone = origDone
	})

	assert.NoError(t, ConfigureHandle(HandleOptions{DisableVFInfoCollection: true}))
	assert.NotEqual(t, orig, pkgHandle)
	assert.NoError(t, pkgHandle.Close())
	assert.Error(t, ConfigureHandle(HandleOptions{}))
}

func TestNewHandleWithOptions(t *testing.T) {
	none := netns.None()
	tests := []struct {
		name           string
		opts           HandleOptions
		nlFamilies     []int
		wantSocketless bool
	}{
		{
			name:           "disable VF only",
			opts:           HandleOptions{DisableVFInfoCollection: true},
			wantSocketless: true,
		},
		{
			name: "retry interrupted",
			opts: HandleOptions{
				DisableVFInfoCollection: true,
				RetryInterrupted:        true,
			},
		},
		{
			name: "explicit namespace",
			opts: HandleOptions{
				DisableVFInfoCollection: true,
				NetNS:                   &none,
			},
		},
		{
			name:       "explicit netlink family",
			opts:       HandleOptions{DisableVFInfoCollection: true},
			nlFamilies: []int{unix.NETLINK_ROUTE},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewHandleWithOptions(tt.opts, tt.nlFamilies...)
			if !assert.NoError(t, err) {
				return
			}
			t.Cleanup(func() { assert.NoError(t, h.Close()) })

			assert.True(t, h.options.DisableVFInfoCollection)
			if tt.wantSocketless {
				assert.Nil(t, h.sockets)
			} else {
				assert.NotNil(t, h.sockets)
			}

			req := h.newNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_DUMP)
			if tt.wantSocketless {
				assert.Nil(t, req.Sockets)
			} else {
				assert.NotNil(t, req.Sockets)
			}
		})
	}
}
