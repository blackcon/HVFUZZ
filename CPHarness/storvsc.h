#pragma warning(disable:4201)	// Disable  warning C4201: 비표준 확장이 사용됨: 구조체/공용 구조체의 이름이 없습니다.

/*
 * Packet Flags:
 *
 * This flag indicates that the server should send back a completion for this
 * packet.
 */
#define REQUEST_COMPLETION_FLAG	0x1

#define STORVSC_MAX_CMD_LEN			0x10
#define POST_WIN7_STORVSC_SENSE_BUFFER_SIZE	0x14
#define PRE_WIN8_STORVSC_SENSE_BUFFER_SIZE	0x12

#define STORVSC_SENSE_BUFFER_SIZE		0x14
#define STORVSC_MAX_BUF_LEN_WITH_PADDING	0x14

 /*
  * SRB status codes and masks; a subset of the codes used here.
#define SRB_STATUS_AUTOSENSE_VALID	0x80
#define SRB_STATUS_QUEUE_FROZEN		0x40
#define SRB_STATUS_INVALID_LUN	0x20
#define SRB_STATUS_SUCCESS	0x01
#define SRB_STATUS_ABORTED	0x02
#define SRB_STATUS_ERROR	0x04
#define SRB_STATUS_DATA_OVERRUN	0x12
  */

#define SRB_STATUS_PENDING 0x00
#define SRB_STATUS_SUCCESS 0x01
#define SRB_STATUS_ABORTED 0x02
#define SRB_STATUS_ABORT_FAILED 0x03
#define SRB_STATUS_ERROR 0x04
#define SRB_STATUS_BUSY 0x05
#define SRB_STATUS_INVALID_REQUEST 0x06
#define SRB_STATUS_INVALID_PATH_ID 0x07
#define SRB_STATUS_NO_DEVICE 0x08
#define SRB_STATUS_TIMEOUT 0x09
#define SRB_STATUS_SELECTION_TIMEOUT 0x0A
#define SRB_STATUS_COMMAND_TIMEOUT 0x0B
#define SRB_STATUS_MESSAGE_REJECTED 0x0D
#define SRB_STATUS_BUS_RESET 0x0E
#define SRB_STATUS_PARITY_ERROR 0x0F
#define SRB_STATUS_REQUEST_SENSE_FAILED 0x10
#define SRB_STATUS_NO_HBA 0x11
#define SRB_STATUS_DATA_OVERRUN 0x12
#define SRB_STATUS_UNEXPECTED_BUS_FREE 0x13
#define SRB_STATUS_PHASE_SEQUENCE_FAILURE 0x14
#define SRB_STATUS_BAD_SRB_BLOCK_LENGTH 0x15
#define SRB_STATUS_REQUEST_FLUSHED 0x16
#define SRB_STATUS_INVALID_LUN 0x20
#define SRB_STATUS_INVALID_TARGET_ID 0x21
#define SRB_STATUS_BAD_FUNCTION 0x22
#define SRB_STATUS_ERROR_RECOVERY 0x23
#define SRB_STATUS_NOT_POWERED 0x24
#define SRB_STATUS_INTERNAL_ERROR 0x30
  // (used by the port driver to indicate that a non - scsi - related error occurred)
  // 0x38 - 0x3f = Srb status values reserved for internal port driver use.

  /*
	  SCSI Status Code (SCSI.h)
  0x00 = SCSISTAT_GOOD
  0x02 = SCSISTAT_CHECK_CONDITION
  0x04 = SCSISTAT_CONDITION_MET
  0x08 = SCSISTAT_BUSY
  0x10 = SCSISTAT_INTERMEDIATE
  0x14 = SCSISTAT_INTERMEDIATE_COND_MET
  0x18 = SCSISTAT_RESERVATION_CONFLICT
  0x22 = SCSISTAT_COMMAND_TERMINATED
  0x28 = SCSISTAT_QUEUE_FULL
  */

  /*  Packet structure describing virtual storage requests. */
enum vstor_packet_operation {
	VSTOR_OPERATION_COMPLETE_IO = 1,
	VSTOR_OPERATION_REMOVE_DEVICE = 2,
	VSTOR_OPERATION_EXECUTE_SRB = 3,
	VSTOR_OPERATION_RESET_LUN = 4,
	VSTOR_OPERATION_RESET_ADAPTER = 5,
	VSTOR_OPERATION_RESET_BUS = 6,
	VSTOR_OPERATION_BEGIN_INITIALIZATION = 7,
	VSTOR_OPERATION_END_INITIALIZATION = 8,
	VSTOR_OPERATION_QUERY_PROTOCOL_VERSION = 9,
	VSTOR_OPERATION_QUERY_PROPERTIES = 10,
	VSTOR_OPERATION_ENUMERATE_BUS = 11,		// not used in vstorvsp
	VSTOR_OPERATION_FCHBA_DATA = 12,
	VSTOR_OPERATION_CREATE_SUB_CHANNELS = 13,
	VSTOR_OPERATION_MAXIMUM = 13
};

/*
 * WWN packet for Fibre Channel HBA
 */

struct hv_fc_wwn_packet {
	unsigned __int8	primary_active;
	unsigned __int8	reserved1[3];
	unsigned __int8	primary_port_wwn[8];
	unsigned __int8	primary_node_wwn[8];
	unsigned __int8	secondary_port_wwn[8];
	unsigned __int8	secondary_node_wwn[8];
};

struct vmscsi_win8_extension {
	/*
	 * The following were added in Windows 8
	 */
	unsigned __int16 reserve;
	unsigned __int8  queue_tag;
	unsigned __int8  queue_action;
	unsigned __int32 srb_flags;
	unsigned __int32 time_out_value;
	unsigned __int32 queue_sort_ey;
};

struct vmstorage_channel_properties {
	unsigned __int32 reserved;
	unsigned __int16 max_channel_cnt;
	unsigned __int16 reserved1;

	unsigned __int32 flags;
	unsigned __int32   max_transfer_bytes;

	unsigned __int64  reserved2;
};

/*  This structure is sent during the storage protocol negotiations. */
struct vmstorage_protocol_version {
	/* Major (MSW) and minor (LSW) version numbers. */
	unsigned __int16 major_minor;

	/*
	 * Revision number is auto-incremented whenever this file is changed
	 * (See FILL_VMSTOR_REVISION macro above).  Mismatch does not
	 * definitely indicate incompatibility--but it does indicate mismatched
	 * builds.
	 * This is only used on the windows side. Just set it to 0.
	 */
	unsigned __int16 revision;
};
/*
ffff948e`0dd3fc68  03 00 00 00 01 00 00 00 - 00 00 00 00 00 00 00 00  ................
ffff948e`0dd3fc78  42 4b 00 00 00 00 00 00 - 03 0a 00 00 00 00 00 00  BK..............
ffff948e`0dd3fc88  12 00 00 00 00 00 00 00 - 00 00 00 00 00 00 00 00  ................
ffff948e`0dd3fc98  00 00 00 00 00 00 00 00 - 00 00 00 00 00 00 00 00  ................
*/
struct vmscsi_request {
	unsigned __int16 length;	// 0x0, length >= 0x24 (storvsp: 1C000813A)
	unsigned __int8 srb_status;	// 0x2
	unsigned __int8 scsi_status;// 0x3

	unsigned __int8  port_number;	// 0x4
	unsigned __int8  path_id;		// 0x5
	unsigned __int8  target_id;		// 0x6, target_id < 0x80 (storvsp: 1C000814F)
	unsigned __int8  lun;		// 0x7, lun != 0xff (storvsp: 1C0008159)

	unsigned __int8  cdb_length;	// 0x8, cdb_len <= 0x10
	unsigned __int8  sense_info_length; // 0x9, sense_info_len <= 0x14
	unsigned __int8  data_in;	// 0xA
	unsigned __int8  reserved;

	unsigned __int32 data_transfer_length;	// 0xc, data_transfer_length == 0 || data_transfer_length == sizeof(mdl_buffer)
	// v3 = 1;
	// if ( !checksum_body_v7 && !srb_v1->data_transfer_length_C )
	// return v3;

	union {	// 0x10
		unsigned __int8 cdb[STORVSC_MAX_CMD_LEN];
		unsigned __int8 sense_data[STORVSC_SENSE_BUFFER_SIZE];
		unsigned __int8 reserved_array[STORVSC_MAX_BUF_LEN_WITH_PADDING];
	};
	/*
	 * The following was added in win8.
	 */
	struct vmscsi_win8_extension win8_extension;
};


struct vstor_packet {							// total size of vstor_packet is 64 bytes;
	/* Requested operation type */
	enum vstor_packet_operation operation;		// 4bytes

	/*  Flags - see below for values */
	unsigned __int32 flags;						// 4bytes

	/* Status of the request returned from the server side. */
	unsigned __int32 status;					// 4bytes

	/* Data payload area */
	union {
		/*
		 * Structure used to forward SCSI commands from the
		 * client to the server.
		 */
		struct vmscsi_request vm_srb;

		/* Structure used to query channel properties. */
		struct vmstorage_channel_properties storage_channel_properties;

		/* Used during version negotiations. */
		struct vmstorage_protocol_version version;

		/* Fibre channel address packet */
		struct hv_fc_wwn_packet wwn_packet;

		/* Number of sub-channels to create */
		unsigned __int16 sub_channel_count;

		/* This will be the maximum of the union members */
		unsigned __int8  buffer[0x34];
	};
};