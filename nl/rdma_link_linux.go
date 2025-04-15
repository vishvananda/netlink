package nl

const (
	RDMA_NL_GET_CLIENT_SHIFT = 10
)

const (
	RDMA_NL_NLDEV = 5
)

const (
	RDMA_NLDEV_CMD_GET      = 1
	RDMA_NLDEV_CMD_SET      = 2
	RDMA_NLDEV_CMD_NEWLINK  = 3
	RDMA_NLDEV_CMD_DELLINK  = 4
	RDMA_NLDEV_CMD_SYS_GET  = 6
	RDMA_NLDEV_CMD_SYS_SET  = 7
	RDMA_NLDEV_CMD_RES_GET  = 9
	RDMA_NLDEV_CMD_STAT_GET = 17
)

const (
	RDMA_NLDEV_ATTR_DEV_INDEX                  = 1
	RDMA_NLDEV_ATTR_DEV_NAME                   = 2
	RDMA_NLDEV_ATTR_PORT_INDEX                 = 3
	RDMA_NLDEV_ATTR_CAP_FLAGS                  = 4
	RDMA_NLDEV_ATTR_FW_VERSION                 = 5
	RDMA_NLDEV_ATTR_NODE_GUID                  = 6
	RDMA_NLDEV_ATTR_SYS_IMAGE_GUID             = 7
	RDMA_NLDEV_ATTR_SUBNET_PREFIX              = 8
	RDMA_NLDEV_ATTR_LID                        = 9
	RDMA_NLDEV_ATTR_SM_LID                     = 10
	RDMA_NLDEV_ATTR_LMC                        = 11
	RDMA_NLDEV_ATTR_PORT_STATE                 = 12
	RDMA_NLDEV_ATTR_PORT_PHYS_STATE            = 13
	RDMA_NLDEV_ATTR_DEV_NODE_TYPE              = 14
	RDMA_NLDEV_ATTR_RES_SUMMARY                = 15
	RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY          = 16
	RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_NAME     = 17
	RDMA_NLDEV_ATTR_RES_SUMMARY_ENTRY_CURR     = 18
	RDMA_NLDEV_ATTR_NDEV_NAME                  = 51
	RDMA_NLDEV_ATTR_LINK_TYPE                  = 65
	RDMA_NLDEV_SYS_ATTR_NETNS_MODE             = 66
	RDMA_NLDEV_NET_NS_FD                       = 68
	RDMA_NLDEV_ATTR_STAT_HWCOUNTERS            = 80
	RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY       = 81
	RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY_NAME  = 82
	RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY_VALUE = 83
)
