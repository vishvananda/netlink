package nl

const (
	LWT_BPF_PROG_UNSPEC = iota
	LWT_BPF_PROG_FD
	LWT_BPF_PROG_NAME
	__LWT_BPF_PROG_MAX
)

const (
	LWT_BPF_PROG_MAX = __LWT_BPF_PROG_MAX - 1
)

const (
	LWT_BPF_UNSPEC = iota
	LWT_BPF_IN
	LWT_BPF_OUT
	LWT_BPF_XMIT
	LWT_BPF_XMIT_HEADROOM
	__LWT_BPF_MAX
)

const (
	LWT_BPF_MAX = __LWT_BPF_MAX - 1
)

const (
	LWT_BPF_MAX_HEADROOM = 256
)
