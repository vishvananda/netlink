package netlink

import (
	"fmt"
	"testing"
)

func TestQdiscAddDel(t *testing.T) {
	// eth0, _ := LinkByName("eth0")
	qdiscs, err := QdiscList(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, qdisc := range qdiscs {
		fmt.Printf("Qdisc: %v\n", qdisc)
		switch qdisc.Type() {
		case "pfifo_fast":
			pfifo := qdisc.(*PfifoFast)
			fmt.Printf("pfifo: %v %v\n", pfifo.Bands, pfifo.PriorityMap)
		case "tbf":
			fmt.Printf("tbf: %v\n", qdisc.(*TokenBucketFilter))
		}
	}
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
}
