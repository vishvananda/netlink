package netlink

import (
	"bytes"
	"github.com/vishvananda/netns"
	"log"
	"os"
	"reflect"
	"runtime"
	"testing"
)

type tearDownNetlinkTest func()

func setUpNetlinkTest(t *testing.T) tearDownNetlinkTest {
	if os.Getuid() != 0 {
		msg := "Skipped test because it requires root privileges."
		log.Printf(msg)
		t.Skip(msg)
	}

	// new temporary namespace so we don't pollute the host
	// lock thread since the namespace is thread local
	runtime.LockOSThread()
	var err error
	ns, err := netns.New()
	if err != nil {
		t.Fatal("Failed to create newns", ns)
	}

	return func() {
		ns.Close()
		runtime.UnlockOSThread()
	}
}

type testSerializer interface {
	serializeSafe() []byte
	Serialize() []byte
}

func testDeserializeSerialize(t *testing.T, orig []byte, safemsg testSerializer, msg testSerializer) {
	if !reflect.DeepEqual(safemsg, msg) {
		t.Fatal("Deserialization failed.\n", safemsg, "\n", msg)
	}
	safe := msg.serializeSafe()
	if !bytes.Equal(safe, orig) {
		t.Fatal("Safe serialization failed.\n", safe, "\n", orig)
	}
	b := msg.Serialize()
	if !bytes.Equal(b, safe) {
		t.Fatal("Serialization failed.\n", b, "\n", safe)
	}

}
