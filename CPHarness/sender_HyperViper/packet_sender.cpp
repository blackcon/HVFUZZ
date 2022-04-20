/*

Copyright (C) 2017 Robert Gawlik

This file is part of kAFL Fuzzer (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <random>
#include <ctime>
#include <functional>
#include <iostream>
#include "HVdef.h"
#include "HVUdefs.h"
#include "HVdriverIO.h"
#include "Convertions.h"
#include "storvsc.h"

using namespace std;

#define IOCTL_SEND_PACKET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define PAYLOAD_SIZE						(128 << 10)				/* up to 128KB payloads */

typedef struct {
    UINT32 size;
    UINT8 data[PAYLOAD_SIZE - sizeof(INT32) - sizeof(INT8)];
    UINT8 redqueen_mode;
} kAFL_payload;

// storvsp!VspValidateRequest() 중 cdb 검사 루틴 
unsigned int valid_cdb(unsigned int v4)
{
    unsigned int v5, v8, v9, v10, v11, v12, v13, v14;
    //unsigned long v6;
    bool checksum_body_v7;
    if (v4 > 0x46)
    {
        v8 = v4 - 0x5A;
        if (!v8)
            return 6;
        v9 = v8 - 0x2E;
        if (!v9)
            return 6;
        v10 = v9 - 2;
        if (!v10)
            return 6;
        v11 = v10 - 0x16;
        if (!v11)
            return 6;
        v12 = v11 - 8;
        if (!v12)
            return 6;
        v13 = v12 - 2;
        if (!v13)
            return 6;
        v14 = v13 - 3;
        if (!v14)
            return 6;
        checksum_body_v7 = v14 == 16;
    }
    else
    {
        v5 = v4 - 8;
        if ((unsigned int)v5 <= 0x3E)
        {
            unsigned char deny_bit[] = { 0x0, 0x3, 0x4, 0x1c, 0x1e, 0x21, 0x2c, 0x34, 0x3c, 0x3e };
            for (int j = 0; j < sizeof(deny_bit); j++) {
                if (deny_bit[j] == v5)
                    return 6;
            }
            //v6 = 0x4C00000520040405;
            //if ( _bittest64(&v6, v5) )
            //      return 6;
        }
        checksum_body_v7 = v4 == 3;
    }
    if (!checksum_body_v7)
        return 1;
    return 6;
}


PVOID GeneratePacket()
{
	BOOL showProgress = TRUE;
	FILE* fin;
	char* buffer1 = NULL, * MdlBuffer = NULL;
	DWORD buffer1Len = 0, MdlBuffer_len = 0;
	
	/*
	* Sample Packet
	* 03 00 00 00 01 00 00 00 00 00 00 00 34 00 00 00  <-- 0xc
	* 00 00 00 00 0C 14 01 00 10 00 00 00 A0 00 00 00  <-- 0x14, 0x15, 0x16, 0x18, 0xc
	* 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00  <-- 0x25
	* 00 00 53 00 58 01 08 00 0A 00 00 00 00 00 00 00  <-- 0x32, 0x34, 0x35, 0x36, 0x38
	*/
	struct vstor_packet* packet = NULL;

	packet = (struct vstor_packet*)malloc(sizeof(struct vstor_packet));
	if (packet == NULL) {
		printf(" [-] Fail to allocate vstor_packet\n");
		return NULL;
	}
	/////////// set Operation of packet ////////////
	memset(packet, 0, sizeof(struct vstor_packet));	// Init buffer;
	packet->flags = 1;	// packet + 0x4
	packet->status = 0;	// packet + 0x8
	if ((MdlBuffer_len > 0) && (MdlBuffer != NULL)) {
		memset(MdlBuffer, 0, MdlBuffer_len);
		MdlBuffer_len = 0;
		delete MdlBuffer;
	}

	// Assemble the attack packet
	//UINT8 op = 0; // Set op is VSTOR_OPERATION_EXECUTE_SRB For Fuzzing
	//UINT8 fuzz_cmd[] = { 7, 8, 9, 0xA, 0xC, 0xD };
	//op = fuzz_cmd[rand() % sizeof(fuzz_cmd)];
	UINT8 op = VSTOR_OPERATION_EXECUTE_SRB;

	if (op == VSTOR_OPERATION_COMPLETE_IO) {	// 1 :: Host return 0xC0000010
		packet->operation = VSTOR_OPERATION_COMPLETE_IO;
		// do not set the body(buffer)
	}
	else if (op == VSTOR_OPERATION_REMOVE_DEVICE) {	// 2 ::Host  return 0xC0000010
		packet->operation = VSTOR_OPERATION_REMOVE_DEVICE;
		// do not set the body(buffer)
	}
	else if (op == VSTOR_OPERATION_EXECUTE_SRB) {	// 3 :: Host return 0xC0000010
		/*
		packet->operation = VSTOR_OPERATION_EXECUTE_SRB;	// packet + 0x0:: 03
		packet->flags = 1;	// packet + 0x4
		packet->status = 0;	// packet + 0x8

		packet->vm_srb.length = 0x34;	// packet + 0xc
		packet->vm_srb.srb_status = 0;
		packet->vm_srb.scsi_status = 0;
		packet->vm_srb.port_number = 0;
		packet->vm_srb.path_id = 0;
		packet->vm_srb.target_id = 0;
		packet->vm_srb.lun = 0;

		packet->vm_srb.cdb_length = 0x10;
		packet->vm_srb.sense_info_length = 0x14;

		packet->vm_srb.data_in = 1;
		packet->vm_srb.reserved = 0;

		packet->vm_srb.cdb[0] = 0x12;
		memset(&packet->vm_srb.cdb[1], 0x61, packet->vm_srb.cdb_length);

		// ?????????????? //
		packet->vm_srb.win8_extension.reserve = 0;
		packet->vm_srb.win8_extension.queue_tag = 0x53;
		packet->vm_srb.win8_extension.queue_action = 0;
		packet->vm_srb.win8_extension.srb_flags = 0x080158;
		packet->vm_srb.win8_extension.time_out_value = 0xA;
		packet->vm_srb.win8_extension.queue_sort_ey = 0x0;
		*/
		packet->operation = VSTOR_OPERATION_EXECUTE_SRB;	// packet + 0x0

		((PUINT8)packet)[0xC] = 0x34;	// vm_srb.length == 0x0034
		((PUINT8)packet)[0xE] = 0;	// vm_srb.srb_status // 2
		((PUINT8)packet)[0xF] = 0;	// vm_srb.scsi_status // 3

		((PUINT8)packet)[0x10] = 0;	// vm_srb.port_number // 4
		((PUINT8)packet)[0x11] = 0;	// // vm_srb.path_id < 0x100 // 5

		// packet->vm_srb.target_id = 0x00; // 0x12 (only zero, for finding devie_object at VspAdapterFindDeviceLocked())
		((PUINT8)packet)[0x12] = 0;	// vm_srb.target_id < 0x80 // 6
		// packet->vm_srb.lun = 0x00;		// 0x13 (only zero, for finding devie_object at VspAdapterFindDeviceLocked())
		((PUINT8)packet)[0x13] = 0;	// vm_srb.lun < 0xFF // 7
									// MDL 전달 시, VSP REQUEST TYPE이 READ_TYPE 일 경우 항상 0이어야 함

		//packet->vm_srb.cdb_length = rand() % 0x11; // <= 0x10
		((PUINT8)packet)[0x14] = rand() % 0x11;	// vm_srb.cdb_length <= 0x10 // 8
		//packet->vm_srb.sense_info_length = rand() % 0x15; // <= 0x14
		((PUINT8)packet)[0x15] = rand() % 0x15;	// vm_srb.sense_info_length <= 0x14 // 9 

		((PUINT8)packet)[0x16] = 0x00;	// vm_srb.data_in 
		((PUINT8)packet)[0x17] = 0x00;	// vm_srb.reserved

		// Choose MDL using
		DWORD choose_mdl_len[] = { 0, 0x10, rand() % 0x100000000 };
		MdlBuffer_len = choose_mdl_len[rand() % (sizeof(choose_mdl_len) / 4)];
		if (MdlBuffer_len == 0) {
			// packet->vm_srb.data_transfer_length = 0; // data_transfer_length == 0
			((PUINT8)packet)[0x18] = 0;	// vm_srb.data_transfer_length
			((PUINT8)packet)[0x19] = 0;	// vm_srb.data_transfer_length
			((PUINT8)packet)[0x1a] = 0;	// vm_srb.data_transfer_length
			((PUINT8)packet)[0x1b] = 0;	// vm_srb.data_transfer_length
		}
		else if (MdlBuffer_len != 0) {
			// Set MDL data (check size in storvsp!VspIsValidSgRequest())
			// UINT8 ValidSgRequest[] = { 0x8, 0xA, 0x28, 0x2A, 0x88, 0x8A, 0xA8, 0xAA };
			// ((PUINT8)packet)[0x1c] = ValidSgRequest[rand() % sizeof(ValidSgRequest)];	// VSP REQUEST TYPE using storvsp!VspGetRequestType 

			// Allocate MdlBuffer
			MdlBuffer = new char[MdlBuffer_len];
			for (int index = 0; index < MdlBuffer_len; index++) {
				memset(MdlBuffer + index, rand() % 0x100, 1);
			}

			((PUINT8)packet)[0x18] = (MdlBuffer_len & 0x000000ff) >> 0x0;	// vm_srb.data_transfer_length == sizeof(mdl_buffer)
			((PUINT8)packet)[0x19] = (MdlBuffer_len & 0x0000ff00) >> 0x8;	// vm_srb.data_transfer_length
			((PUINT8)packet)[0x1a] = (MdlBuffer_len & 0x00ff0000) >> 0x10;	// vm_srb.data_transfer_length
			((PUINT8)packet)[0x1b] = (MdlBuffer_len & 0xff000000) >> 0x18;	// vm_srb.data_transfer_length
		}

		// Set Body Data
		UINT8 VspGetRequestType[] = {	// call valid_cdb()
			0x3, 0x8, 0xb, 0xc, 0x12, 0x24, 0x26, 0x29, 0x2A,
			0x34, 0x3c, 0x44, 0x46, 0x5a, 0x88, 0x8a, 0xa0,
			0xa8, 0xaa, 0xad,  0xbd, rand() % 0x100
		}; // If Fuzzer use the MDL, cdb_vlue is 0xax or 0x12 (ref: 1C0007DC7 on VspStartJob) 
		((PUINT8)packet)[0x1c] = VspGetRequestType[rand() % sizeof(VspGetRequestType)];	// VSP REQUEST TYPE using storvsp!VspGetRequestType 
										// 0xA0 : VspAdapterHandleReportLuns() - write mode :: Host -> guest 로 전달
										// 0x12 :VspHandleAbsentLun0Inquiry() && VspAdapterHandleInquiry
										// 0x8A : UNKNWON TYPE
		if (((PUINT8)packet)[0x1c] == 0xA0) {
			((PUINT8)packet)[0x16] = (rand() % 0xff) + 1;	// Must be not Zero (storvsp!VspAdapterHandleReportLuns )
		}
		else if (((PUINT8)packet)[0x1c] == 0x12) {
			((PUINT8)packet)[0x16] = (rand() % 0xff) + 1;	// Must be not Zero (storvsp!VspHandleAbsentLun0Inquiry )
		}
		// CDB Data
		for (int k = 0x1d; k < 0x2c; k++) {
			((PUINT8)packet)[k] = rand() % 0x100; // 0x02;	// ??
		}

		// Unknown value..
		((PUINT8)packet)[0x33] = rand() % 0x100; //0x20;	// ??
		((PUINT8)packet)[0x34] = rand() % 0x100; //0x80;	// ??
		((PUINT8)packet)[0x35] = rand() % 0x100; //0x03;	// ??
		((PUINT8)packet)[0x36] = rand() % 0x100; //0x20;	// ??
		((PUINT8)packet)[0x37] = rand() % 0x100; //0x40;	// ??
		((PUINT8)packet)[0x38] = rand() % 0x100; //0x41;	// ??
		((PUINT8)packet)[0x3c] = rand() % 0x100; //0xa8;	// ??
		((PUINT8)packet)[0x3d] = rand() % 0x100; //0x2d;	// ??
		((PUINT8)packet)[0x3e] = rand() % 0x100; //0x3e;	// ??
		((PUINT8)packet)[0x3f] = rand() % 0x100; //0x02;	// ??
		
	}
	else if (op == VSTOR_OPERATION_RESET_LUN) {	// 4 <-- If this choose a operation, whill be exit the fuzzer.
		packet->operation = VSTOR_OPERATION_RESET_LUN;
		// do not set the body(buffer)

		// logic below code at storvsc
		// if (*guest_input_buffer_v11 == 3)
		//  	BYTE2(client_context_v9->vmscsi_request88) = 4;
		// client_context_v9->ERROR_CODE = ret_v17;
		// *guest_input_buffer_v11 = 1;                  // VSTOR_OPERATION_COMPLETE_IO
		// VmbChannelPacketComplete( input_packet_a2, &client_context_v9->guest_input_buffer_7c, client_context_v9->defaultsize_78);
	}
	else if (op == VSTOR_OPERATION_RESET_ADAPTER) {	// 5 
		packet->operation = VSTOR_OPERATION_RESET_ADAPTER;
		// do not set the body(buffer)

		// logic below code at storvsc
		// if (*guest_input_buffer_v11 == 3)
		//  	BYTE2(client_context_v9->vmscsi_request88) = 4;
		// client_context_v9->ERROR_CODE = ret_v17;
		// *guest_input_buffer_v11 = 1;                  // VSTOR_OPERATION_COMPLETE_IO
		// VmbChannelPacketComplete( input_packet_a2, &client_context_v9->guest_input_buffer_7c, client_context_v9->defaultsize_78);
	}
	else if (op == VSTOR_OPERATION_RESET_BUS) {	// 6
		packet->operation = VSTOR_OPERATION_RESET_BUS;
		// do not set the body(buffer)

		// logic below code at storvsc
		// if (*guest_input_buffer_v11 == 3)
		//  	BYTE2(client_context_v9->vmscsi_request88) = 4;
		// client_context_v9->ERROR_CODE = ret_v17;
		// *guest_input_buffer_v11 = 1;                  // VSTOR_OPERATION_COMPLETE_IO
		// VmbChannelPacketComplete( input_packet_a2, &client_context_v9->guest_input_buffer_7c, client_context_v9->defaultsize_78);
	}
	else if (op == VSTOR_OPERATION_BEGIN_INITIALIZATION) {	// 7
		// VStorProtocolStateMachineRun(vAdapter_v16, 1, 0i64);
		packet->operation = VSTOR_OPERATION_BEGIN_INITIALIZATION;
	}
	else if (op == VSTOR_OPERATION_END_INITIALIZATION) {	// 8 
		// VStorProtocolStateMachineRun(vAdapter_v16, 4, 0i64);
		packet->operation = VSTOR_OPERATION_END_INITIALIZATION;
	}
	else if (op == VSTOR_OPERATION_QUERY_PROTOCOL_VERSION) {	// 9
		// VStorProtocolStateMachineRun(vAdapter_v16, 2, (__int64)client_context_v9->guest_input_buffer_7c);
		packet->operation = VSTOR_OPERATION_QUERY_PROTOCOL_VERSION;

		UINT16 version_info[] = { 0x602, 0x600, 0x501, 0x402, 0x200, rand() % 0x10000 };
		UINT16 version = version_info[(UINT8)(rand() % (sizeof(version_info) / 2))];
		((PUINT8)packet)[0xC] = version & 0x00ff;	// packet->version.major_minor
		((PUINT8)packet)[0xD] = (version & 0xff00) >> 0x8;	// packet->version.major_minor
		((PUINT8)packet)[0xE] = 0;	// packet->version.revision 

	}
	else if (op == VSTOR_OPERATION_QUERY_PROPERTIES) {	// A
		// VStorProtocolStateMachineRun(vAdapter_v16, 3, (__int64)client_context_v9->guest_input_buffer_7c);
		//   -> VStorProtocolPropertiesQueried() 
		packet->operation = VSTOR_OPERATION_QUERY_PROPERTIES;
		/*
		* // Set data on HOST
		packet->storage_channel_properties.reserved		= rand() % 0x100000000;	// 4 byte
		packet->storage_channel_properties.max_channel_cnt = rand() % 0x10000;	// 2byte

		packet->storage_channel_properties.reserved1	= rand() % 0x10000;// 2byte
		packet->storage_channel_properties.flags = rand() % 0x100000000;	// 4byte

		packet->storage_channel_properties.max_transfer_bytes = rand() % 0x100000000; // 4byte

		packet->storage_channel_properties.reserved2	= rand() % 0xffffffffffffffff;	// 8byte
		*/
	}
	else if (op == VSTOR_OPERATION_ENUMERATE_BUS) {	// B
		//  (not used in vstorvsp) 
		return NULL;
	}
	else if (op == VSTOR_OPERATION_FCHBA_DATA) {	// C
		packet->operation = VSTOR_OPERATION_FCHBA_DATA;
		/*
		* // Set data on HOST
		packet->wwn_packet.primary_active = rand() % 0x100;
		packet->wwn_packet.reserved1[rand()%3] = rand() % 0x100;
		packet->wwn_packet.primary_port_wwn[rand() % 8] = rand() % 0x100;
		packet->wwn_packet.primary_node_wwn[rand() % 8] = rand() % 0x100;
		packet->wwn_packet.secondary_port_wwn[rand() % 8] = rand() % 0x100;
		packet->wwn_packet.secondary_node_wwn[rand() % 8] = rand() % 0x100;
		*/
	}
	else if (op == VSTOR_OPERATION_CREATE_SUB_CHANNELS) {	// D
		packet->operation = VSTOR_OPERATION_CREATE_SUB_CHANNELS;
		((PUINT8)packet)[0xC] = (UINT16)(rand() % 0xffff);	// packet->sub_channel_count
	}
	else {
		printf(" [-] Do not use Command: %x\n", op);
		return NULL;
	}
	//printf("\n [+] input packet: size = 0x%X, operation = 0x%X, buffer = 0x%X, seed = %llx", 0x40, packet->operation, *(PUINT16)packet->buffer, seed);
	for (DWORD i = 0; i < sizeof(struct vstor_packet); i++) {	// original size of packet is 0x40;
		if (i % 0x10 == 0) {
			printf("\n");
		}
		printf("%02X ", *(UINT8*)((UINT64)packet + i));
	}
	printf("\n");
	if (MdlBuffer_len > 0) {
		printf("\n [+] input MDL: size = 0x%X", MdlBuffer_len);
		for (DWORD i = 0; i < MdlBuffer_len; i++) {	// original size of packet is 0x40;
			if (i % 0x10 == 0) {
				printf("\n");
			}
			if (i > 0x40) {
				printf(" -- \nSNIP byte :%X -- \n", (MdlBuffer_len - 0x40));
				break;
			}
			printf("%02X ", *(UINT8*)((UINT64)MdlBuffer + i));
		}
		printf("\n");
	}

	//if (!driver.channelsSend(guid, (PVOID)packet, 0x40, MdlBuffer, MdlBuffer_len)) {
	//	ERROR_EXIT("Sending packet to channel failed");
	//}
	return NULL;
}
UINT32 GenerateSRB( PUINT8 packet) 
{
	UINT8 default_srb_size = 0x34;
	packet[0] = default_srb_size & 0xff;	// packet + 0xC (vmscsi_request + 0) :: vm_srb.length == 0x0034
	packet[1] = default_srb_size & 0xff00;	// packet + 0xC (vmscsi_request + 0) :: vm_srb.length == 0x0034

	packet[2] = 0;	// packet + 0xE (vmscsi_request + 2) :: vm_srb.srb_status
	packet[3] = 0;	// packet + 0xF (vmscsi_request + 3) :: vm_srb.scsi_status 
	packet[4] = 0;	// packet + 0x10 (vmscsi_request + 4) :: vm_srb.port_number 
	packet[5] = 0;	// packet + 0x11 (vmscsi_request + 5) :: vm_srb.path_id < 0x100 

	// packet->vm_srb.target_id = 0x00; // 0x12 (only zero, for finding devie_object at VspAdapterFindDeviceLocked())
	packet[6] = 0;	// packet + 0x12 (vmscsi_request + 6) :: vm_srb.target_id < 0x80

	// packet->vm_srb.lun = 0x00;		// 0x13 (only zero, for finding devie_object at VspAdapterFindDeviceLocked())
	packet[7] = 0;	// packet + 0x13 (vmscsi_request + 7) :: vm_srb.lun < 0xFF 
								// MDL 전달 시, VSP REQUEST TYPE이 READ_TYPE 일 경우 항상 0이어야 함

	//packet->vm_srb.cdb_length = rand() % 0x11; // <= 0x10
	packet[8] = 0x10;	// packet + 0x14 (vmscsi_request + 8) :: vm_srb.cdb_length <= 0x10
	//packet->vm_srb.sense_info_length = rand() % 0x15; // <= 0x14
	packet[9] = 0x14;  // packet + 0x15 (vmscsi_request + 9) ::  vm_srb.sense_info_length <= 0x14 

	packet[0xA] = 0x01;	// packet + 0x16 (vmscsi_request + A) :: vm_srb.data_in 
	packet[0xB] = 0x00;	// packet + 0x17 (vmscsi_request + B) :: vm_srb.reserved


	// Choose MDL using
	DWORD choose_mdl_len[] = { 
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
		0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10,
		rand() % 0x100
	};
	UINT32 MdlBuffer_len = choose_mdl_len[rand() % (sizeof(choose_mdl_len) / 4)];
	if (MdlBuffer_len == 0) {
		packet[0xC] = 0;	//  packet + 0x18 (vmscsi_request + C) :: vm_srb.data_transfer_length == 0
		packet[0xD] = 0;	//  packet + 0x18 (vmscsi_request + D) 
		packet[0xE] = 0;	//  packet + 0x18 (vmscsi_request + E) 
		packet[0xF] = 0;	//  packet + 0x18 (vmscsi_request + F) 
	}
	else if (MdlBuffer_len != 0) {
		// Dataset MdlBuffer
		for (int index = 0; index < MdlBuffer_len; index++) {
			packet[default_srb_size + index] = rand() % 0x100;	// MdlBuffer is packet[0x34:~]
		}
		packet[0xC] = (MdlBuffer_len & 0x000000ff) >> 0x0;	// packet + 0x18 (vmscsi_request + C) :: vm_srb.data_transfer_length == sizeof(mdl_buffer)
		packet[0xD] = (MdlBuffer_len & 0x0000ff00) >> 0x8;	// packet + 0x19 (vmscsi_request + D) :: vm_srb.data_transfer_length
		packet[0xE] = (MdlBuffer_len & 0x00ff0000) >> 0x10;	// packet + 0x1A (vmscsi_request + E) :: vm_srb.data_transfer_length
		packet[0xF] = (MdlBuffer_len & 0xff000000) >> 0x18;	// packet + 0x1B (vmscsi_request + F) :: vm_srb.data_transfer_length

	}
	// CDB (Command Descriptor Block)
	// reference: List of SCSI commands (https://en.wikipedia.org/wiki/SCSI_command#List_of_SCSI_commands)
	UINT8 VspGetRequestType[] = {	// call valid_cdb()
			0x3, 0x8, 0xb, 0xc, 0x12, 0x24, 0x26, 0x29, 0x2A,
			0x34, 0x3c, 0x44, 0x46, 0x5a, 0x88, 0x8a, 0xa0,
			0xa8, 0xaa, 0xad,  0xbd, rand() % 0x100
	}; // If Fuzzer use the MDL, cdb_vlue is 0xAX or 0x12 (ref: 1C0007DC7 on VspStartJob) 
	packet[0x10] = VspGetRequestType[rand() % sizeof(VspGetRequestType)]; // If Fuzzer use the MDL, cdb_vlue is 0xax or 0x12 (ref: 1C0007DC7 on VspStartJob) 
										// VSP REQUEST TYPE using storvsp!VspGetRequestType 
										// 0xA0 : VspAdapterHandleReportLuns() - write mode :: Host -> guest 로 전달
										// 0x12 :VspHandleAbsentLun0Inquiry() && VspAdapterHandleInquiry
										// 0x8A : UNKNWON TYPE
	// CDB Data
	for (int k = 0x11; k < 0x20; k++) {
		packet[k] = rand() % 0x100; //	??
	}

	// Below is Unknown value..
	packet[0x27] = rand() % 0x100;;	// ??
	packet[0x28] = rand() % 0x100;;	// packet + 0x34 (vmscsi_request + 0x28) :: use `vhdparser!NVhdParserExecuteScsiRequestDisk+0xb7`
	packet[0x29] = rand() % 0x100;;	// packet + 0x35 (vmscsi_request + 0x29) :: use `vhdparser!NVhdParserExecuteScsiRequestDisk+0xb7`
	packet[0x2A] = rand() % 0x100;;	// packet + 0x36 (vmscsi_request + 0x2A) :: use `vhdparser!NVhdParserExecuteScsiRequestDisk+0xb7`
	packet[0x2B] = rand() % 0x100;;	// packet + 0x37 (vmscsi_request + 0x2B) :: use `vhdparser!NVhdParserExecuteScsiRequestDisk+0xb7`
	packet[0x2C] = rand() % 0x100;;	// ??
	packet[0x2D] = rand() % 0x100;;	// ??
	packet[0x2E] = rand() % 0x100;;	// ??
	packet[0x2F] = rand() % 0x100;;	// ??
	packet[0x30] = rand() % 0x100;;	// ??
	//////////////////////////////////////////////////////////////////////////////////

	return (UINT32)default_srb_size + MdlBuffer_len;
}
int main(int argc, char** argv)
{
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);
    memset(payload_buffer, 0x00, PAYLOAD_SIZE);

    /* open vulnerable driver */
    HANDLE hHarness = NULL;
    BOOL status = -1;
	
    if (argc > 2) {
		printf(" [+] User Input DeviceName: %s", argv[2]);
        hHarness = CreateFile((LPWSTR)argv[2],
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
    }
    else {
        hHarness = CreateFile(L"\\\\.\\CPHarness",
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
    }

    if (hHarness == INVALID_HANDLE_VALUE) {
        printf("[-] hAFL2 harness: Cannot get device handle: 0x%X\n", GetLastError());
        ExitProcess(0);
    }
    else {
        printf("[+] GET device handle: 0x%X \n", (unsigned int)hHarness);
    }


	VMBUS_CHANNEL_PACKET_FUZZ_CONF conf;
	conf.fuzzIncrementMain = 1;
	conf.fuzzIncrementMdl = 1;
	conf.fuzzRandomMain = 10000;
	conf.fuzzRandomMdl = 10000;


	/// Create the SEED
	//UINT64	seed = _seed;
	//UINT64	seed = 0x1ff4567890ABCDEF;	// some crash 
	mt19937 engine((unsigned int)time(NULL));
	uniform_int<UINT64> distribution(0, 0xffffffff);
	auto generator = bind(distribution, engine);
	UINT64 seed = generator();
	srand(seed);

	CHAR log[0x100] = { 0 };
	FILE *fd = fopen("sender_log.txt", "a+");
	sprintf_s(log, "SEED: %llx\n", seed);
	fwrite(log, strlen(log), 1, fd);
	while (conf.fuzzRandomMain--) {
		// RESET SEED
		if (conf.fuzzRandomMain < 2) {
			seed = generator();
			srand(seed);
			printf("[INFO] %d tries left, Set new seed 0x%llX\n", conf.fuzzRandomMain, seed);
			sprintf_s(log, "[INFO] %d tries left, Set new seed 0x%llX\n", conf.fuzzRandomMain, seed);
			fwrite(log, strlen(log), 1, fd);
			fclose(fd);

			fd = fopen("sender_log.txt", "a+");
			conf.fuzzRandomMain = 10000;
		}
		// Print Log
		if (conf.fuzzRandomMain % 500 == 0) {
			printf("[INFO] Fuzzing main buffer, %d tries left, current seed 0x%llX\n", conf.fuzzRandomMain, seed);
			sprintf_s(log, "[INFO] Fuzzing main buffer, %d tries left, current seed 0x%llX\n", conf.fuzzRandomMain, seed);
			fwrite(log, strlen(log), 1, fd);
			fclose(fd);

			fd = fopen("sender_log.txt", "a+");
		}

		/*
		Generate Packet for SRB
		*/
		payload_buffer->size = GenerateSRB(payload_buffer->data);

		/* Warning: This part won't work well unless you'll patch the VMSwitch packet signal mechanism.
		For more information, read the "VMSwitch Harness Gaps" section within the README.md file of hAFL2. */
		printf("Sending payload with size: 0x%x\n", payload_buffer->size);
		for (DWORD i = 0; i < (UINT32)payload_buffer->data[0]; i++) {	// original size of packet is 0x40;
			if (i % 0x10 == 0) {
				printf("\n");
			}
			printf("%02X ", payload_buffer->data[i]);
		}
		printf("\n");
		
		if (payload_buffer->size > (UINT32)payload_buffer->data[0]) {
			UINT32 MdlBuffer_len = payload_buffer->size - (UINT32)payload_buffer->data[0];
			printf("\n [+] input MDL: size = 0x%X\n", MdlBuffer_len);
			for (DWORD i = (UINT32)payload_buffer->data[0]; i < (UINT32)payload_buffer->data[0]+ MdlBuffer_len; i++) {	// original size of packet is 0x40;
				if (i % 0x10 == 0) {
					printf("\n");
				}
				if (i > 0x80) {
					printf("\n -- SNIP byte :%X -- \n", (MdlBuffer_len - 0x40));
					break;
				}
				printf("%02X ", payload_buffer->data[i]);
			}
			printf("\n");
		}
		

		BOOL ret = DeviceIoControl(hHarness,
			IOCTL_SEND_PACKET,
			(LPVOID)(payload_buffer->data),
			(DWORD)payload_buffer->size,
			NULL,
			0,
			NULL,
			NULL
		);
		printf("RET: %d\n", ret);
	}

    return 0;
}

