// Stubfile to let netlink package compile on macos
// This file is only to make compilation succeed.
// Functionality is NOT supported on macos.

// build +darwin

// Only the definations needed for compilation on MacOs are added here.
// When adding the definitions, copy the corresponding ones from
//	link_linux.go

package netlink

type LinkUpdate struct {
	Link
}
