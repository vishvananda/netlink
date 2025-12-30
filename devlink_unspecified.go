//go:build !linux
// +build !linux

package netlink

// DevLinkGetDeviceList retrieves the list of devlink devices available on the system.
// On non-Linux builds this function is not implemented and returns nil, ErrNotImplemented.
func DevLinkGetDeviceList() ([]*DevlinkDevice, error) {
	return nil, ErrNotImplemented
}

// DevLinkGetDeviceByName looks up the Devlink device identified by the bus and device names.
// On non-Linux builds this always returns nil and ErrNotImplemented.
func DevLinkGetDeviceByName(Bus string, Device string) (*DevlinkDevice, error) {
	return nil, ErrNotImplemented
}

// DevLinkSetEswitchMode sets the eswitch mode of the specified DevlinkDevice to NewMode.
// On platforms where Devlink is not implemented this returns ErrNotImplemented.
func DevLinkSetEswitchMode(Dev *DevlinkDevice, NewMode string) error {
	return ErrNotImplemented
}

// DevLinkGetAllPortList retrieves the list of all devlink ports available on the system.
// On platforms where devlink functionality is unavailable this returns nil and ErrNotImplemented.
func DevLinkGetAllPortList() ([]*DevlinkPort, error) {
	return nil, ErrNotImplemented
}

// DevlinkGetDeviceResources retrieves the resource information for the devlink device specified by bus and device.
// On non-Linux builds this function is unimplemented and returns ErrNotImplemented.
func DevlinkGetDeviceResources(bus string, device string) (*DevlinkResources, error) {
	return nil, ErrNotImplemented
}

// DevlinkGetDeviceParams retrieves the devlink parameters for the device specified by bus and device.
// On non-Linux builds this function is not implemented and returns ErrNotImplemented.
func DevlinkGetDeviceParams(bus string, device string) ([]*DevlinkParam, error) {
	return nil, ErrNotImplemented
}

// DevlinkGetDeviceParamByName retrieves the devlink parameter with the given name for the specified bus and device.
// It returns a pointer to the matching DevlinkParam, or nil and an error if the parameter cannot be obtained.
func DevlinkGetDeviceParamByName(bus string, device string, param string) (*DevlinkParam, error) {
	return nil, ErrNotImplemented
}

// DevlinkSplitPort splits the specified devlink port into the given number of logical ports.
// The function returns ErrNotImplemented on platforms where devlink operations are unavailable.
func DevlinkSplitPort(port *DevlinkPort, count uint32) error {
	return ErrNotImplemented
}

// DevlinkUnsplitPort attempts to unsplit the specified DevlinkPort.
// It always returns ErrNotImplemented on non-Linux platforms.
func DevlinkUnsplitPort(port *DevlinkPort) error {
	return ErrNotImplemented
}

// DevlinkSetDeviceParam sets the named parameter for a devlink device identified by bus and device,
// using cmode to indicate the change mode and value as the new parameter value.
// It returns an error if the parameter could not be set.
func DevlinkSetDeviceParam(bus string, device string, param string, cmode uint8, value interface{}) error {
	return ErrNotImplemented
}

// DevLinkGetPortByIndex retrieves the devlink port identified by the bus, device, and port index.
// On non-Linux builds this function returns nil and ErrNotImplemented.
func DevLinkGetPortByIndex(Bus string, Device string, PortIndex uint32) (*DevlinkPort, error) {
	return nil, ErrNotImplemented
}

// DevLinkPortAdd adds a new devlink port to the specified device.
 // 
 // Bus and Device identify the target device. Flavour selects the port flavour to create;
 // Attrs contains creation attributes for the new port.
 //
 // On success returns the created *DevlinkPort. On unsupported platforms returns nil and ErrNotImplemented.
func DevLinkPortAdd(Bus string, Device string, Flavour uint16, Attrs DevLinkPortAddAttrs) (*DevlinkPort, error) {
	return nil, ErrNotImplemented
}

// DevLinkPortDel deletes the devlink port identified by bus, device, and port index.
// On non-Linux builds this always returns ErrNotImplemented.
func DevLinkPortDel(Bus string, Device string, PortIndex uint32) error {
	return ErrNotImplemented
}

// DevlinkPortFnSet sets function-specific attributes for the devlink port identified
// by the given PCI `Bus` and `Device` strings and `PortIndex`.
// The `FnAttrs` parameter specifies the attributes to apply.
// On non-Linux builds this function is not implemented and returns ErrNotImplemented.
func DevlinkPortFnSet(Bus string, Device string, PortIndex uint32, FnAttrs DevlinkPortFnSetAttrs) error {
	return ErrNotImplemented
}

// DevlinkGetDeviceInfoByName retrieves the DevlinkDeviceInfo for a devlink device identified by its bus and device names.
// On non-Linux builds this function is not implemented and returns ErrNotImplemented.
func DevlinkGetDeviceInfoByName(Bus string, Device string) (*DevlinkDeviceInfo, error) {
	return nil, ErrNotImplemented
}

// DevlinkGetDeviceInfoByNameAsMap returns a map of device information keyed by attribute name for the device identified by bus and device.
// On non-Linux platforms this function returns ErrNotImplemented.
func DevlinkGetDeviceInfoByNameAsMap(Bus string, Device string) (map[string]string, error) {
	return nil, ErrNotImplemented
}