#pragma warning(disable:4244)   // Disable "warning C4244: '=': 'ULONG'에서 'unsigned char'(으)로 변환하면서 데이터가 손실될 수 있습니다."

#include "Driver.h"
#include "Globals.h"
#include "KernelModules.h"
#include "storvsc.h"
#include <Wdm.h>
#include <wdmsec.h>
#include <stdio.h>


#define IOCTL_SEND_PACKET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define NVSP_RNDIS_PKT_SIZE (0x28)
#define STORVSC_PKT_SIZE (0x40)
#define COMPLETION_BUFFER_SIZE (0x1000)
#define HARNESS_POOL_TAG 'SNRH'
#define DOS_DEVICE_NAME  L"\\DosDevices\\CPHarness"
#define NT_DEVICE_NAME  L"\\Device\\CPHarness" 

DECLARE_CONST_UNICODE_STRING(dosDeviceName, DOS_DEVICE_NAME);
DECLARE_CONST_UNICODE_STRING(ntDeviceName, NT_DEVICE_NAME);

typedef VMBCHANNEL* PVMBCHANNEL;
PVMBCHANNEL channel;  // define from hKAFL2
BOOLEAN sentPacketHandled = TRUE;

PCWSTR storvscModulePath = (PCWSTR)L"\\SystemRoot\\System32\\drivers\\storvsc.sys";
PCWSTR vmbkclModulePath = (PCWSTR)L"\\SystemRoot\\System32\\drivers\\vmbkmcl.sys";
PFN_VMB_PACKET_FREE pVmbPacketFree = NULL;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtWdfIoQueueIoDeviceControl;
EVT_WDF_DRIVER_UNLOAD EvtWdfDriverUnload;

PVOID NdisBaseAddress = NULL;
PVOID StorvscBaseAddress = NULL;
PVOID vmbkclBaseAddress = NULL;

PFN_VMB_PACKET_ALLOCATE pVmbPacketAllocate = NULL;
PFN_VMB_PACKET_SET_COMPLETION_ROUTINE pVmbPacketSetCompletionRoutine = NULL;
PFN_VMB_CHANNEL_SEND_SYNCHRONOUS_REQUEST pVmbChannelSendSynchronousRequest = NULL;
PFN_VMB_CHANNEL_ENABLE  pVmbChannelEnable = NULL;
PFN_VMB_PACKET_SEND pVmbPacketSend = NULL;
PFN_VMB_PACKET_SEND_WITH_EXTERNAL_MDL pVmbPacketSendWithExternalMdl = NULL;


PVOID KernelGetProcAddress(PVOID ModuleBase, PCHAR pFunctionName)
{
    ASSERT(ModuleBase && pFunctionName);
    PVOID pFunctionAddress = NULL;

    ULONG size = 0;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)
        RtlImageDirectoryEntryToData(ModuleBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

    ULONG_PTR addr = (ULONG_PTR)(PUCHAR)((UINT64)exports - (UINT64)ModuleBase);

    PULONG functions = (PULONG)((ULONG_PTR)ModuleBase + exports->AddressOfFunctions);
    PSHORT ordinals = (PSHORT)((ULONG_PTR)ModuleBase + exports->AddressOfNameOrdinals);
    PULONG names = (PULONG)((ULONG_PTR)ModuleBase + exports->AddressOfNames);
    ULONG  max_name = exports->NumberOfNames;
    ULONG  max_func = exports->NumberOfFunctions;

    ULONG i;

    for (i = 0; i < max_name; i++)
    {
        ULONG ord = ordinals[i];
        if (i >= max_name || ord >= max_func) {
            return NULL;
        }
        if (functions[ord] < addr || functions[ord] >= addr + size)
        {
            if (strcmp((PCHAR)ModuleBase + names[i], pFunctionName) == 0)
            {
                pFunctionAddress = (PVOID)((PCHAR)ModuleBase + functions[ord]);
                break;
            }
        }
    }
    return pFunctionAddress;
}

NTSTATUS GetModuleAddress(PUNICODE_STRING targetModuleName, PVOID* targetBaseAddr)
{
    NTSTATUS status = STATUS_SUCCESS;
    KERNEL_MODULES kernelModules;
    ULONG numberOfModules;
    UNICODE_STRING currentUnicode = { 0 };
    ANSI_STRING currentAnsi = { 0 };
    LONG stringCompareRes = 0;
    BOOLEAN caseInsensitive = FALSE;
    BOOLEAN allocateDestinationString = TRUE;


    status = InitKernelModules(&kernelModules);
    if (!NT_SUCCESS(status))
    {
        goto exit;
    }

    /* Iterate on all loaded modules, find the base address of a given module */

    status = STATUS_NOT_FOUND;
    numberOfModules = GetKernelModulesCount(&kernelModules);
    for (ULONG i = 0; i < numberOfModules; i++)
    {
        RtlInitAnsiString(&currentAnsi, GetKernelModuleNameByIndex(&kernelModules, i));
        status = RtlAnsiStringToUnicodeString(&currentUnicode, &currentAnsi, allocateDestinationString);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Could not convert an Ansi string to a Unicode one\n");
            goto deinit;
        }

        stringCompareRes = RtlCompareUnicodeString(&currentUnicode, targetModuleName, caseInsensitive);
        if (stringCompareRes)
            continue;

        *targetBaseAddr = GetKernelModuleBaseAddressByIndex(&kernelModules, i);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Found Module %wZ address at %p\n", targetModuleName, *targetBaseAddr);
        status = STATUS_SUCCESS;
        break;
    }

deinit:
    DeinitKernelModules(&kernelModules);
exit:
    return status; 
}

NTSTATUS FindOurMiniportChannel()
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PVOID kmclChannelListLocation = NULL;
    ULONG vmbChannelOffset = 0x7a0;
    GUID _guid, target_guid;
    LONG WPP_MAIN_CB_OFFSET = 0x130E0; //  vmbkmcl.sys build 10.0.19044.1526, offset 0xE4090 ==> vmbkmcl!WPP_MAIN_CB (SUCCESS) , windows hv level2 OS

    // 1) Get kmclChannelListLocation
    if (vmbkclBaseAddress)
    {
        //kmclChannelListLocation =poi(vmbkmcl+0x130e0+WPP_MAIN_CB_OFFSET)+0x20 
        kmclChannelListLocation = (PVOID)((UINT64)vmbkclBaseAddress + WPP_MAIN_CB_OFFSET);   // vmbkmcl!WPP_MAIN_CB
        kmclChannelListLocation = (PVOID)((UINT64)kmclChannelListLocation + 0xA0);          // vmbkmcl!WPP_MAIN_CB.DeviceQueue
        kmclChannelListLocation = (PVOID)(*(PUINT64)kmclChannelListLocation + 0x20);        // vmbkmcl!WPP_MAIN_CB.DeviceQueue.kmclChannelListLocation
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: kmclChannelListLocation: %p\n", kmclChannelListLocation);
    }
    
    if (!kmclChannelListLocation) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Fail to get kmclChannelListLocation: %p\n", kmclChannelListLocation);
        return status;
    }
    else if (kmclChannelListLocation)
    {
        // [+] Find channel - vmstorfl(Synthetic IDE Controller)
        //     InterfaceInstanceID: {32412632 - 86cb - 44a2 - 9b5c - 50d1417354f5}
        target_guid.Data1 = 0x32412632;
        target_guid.Data2 = 0x86cb;
        target_guid.Data3 = 0x44a2;
        target_guid.Data4[0] = 0x9b;
        target_guid.Data4[1] = 0x5c;
        target_guid.Data4[2] = 0x50;
        target_guid.Data4[3] = 0xd1;
        target_guid.Data4[4] = 0x41;
        target_guid.Data4[5] = 0x73;
        target_guid.Data4[6] = 0x54;
        target_guid.Data4[7] = 0xf5;

        // storvsc (Synthetic SCSI Controller)
        // GUID: {ba6163d9 - 04a1 - 4d29 - b605 - 72e2ffb1dc7f}
        target_guid.Data1 = 0xba6163d9;
        target_guid.Data2 = 0x04a1;
        target_guid.Data3 = 0x4d29;
        target_guid.Data4[0] = 0xb6;
        target_guid.Data4[1] = 0x05;
        target_guid.Data4[2] = 0x72;
        target_guid.Data4[3] = 0xe2;
        target_guid.Data4[4] = 0xff;
        target_guid.Data4[5] = 0xb1;
        target_guid.Data4[6] = 0xdc;
        target_guid.Data4[7] = 0x7f;

        // 2) Get First Channel List from kmclChannelListLocation at vmbkmcl.sys
        PVMBCHANNEL channel_list = *((PVMBCHANNEL*)kmclChannelListLocation);
        if (!channel_list || channel_list == kmclChannelListLocation){
            return status;
        }
        channel = (PVMBCHANNEL)((UINT64)channel_list - vmbChannelOffset);

        // 3) Find Channel about storvsc.
        while (TRUE)
        {
            if (channel != *(PVMBCHANNEL*)channel) {
                return status;
            }
            memcpy(&_guid, (PVOID)((UINT64)channel + 0x9C8), sizeof(GUID));
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Searching... {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
                _guid.Data1, _guid.Data2, _guid.Data3,
                _guid.Data4[0], _guid.Data4[1], _guid.Data4[2], _guid.Data4[3],
                _guid.Data4[4], _guid.Data4[5], _guid.Data4[6], _guid.Data4[7]);
            if (!memcmp(&_guid, &target_guid, sizeof(GUID))){
                status = STATUS_SUCCESS;
                
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "=================\n");
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, " [+] Find Channel cunk about STORVSC\n");

                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: [!] Find InterfaceInstanceGUID of target channel {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
                    target_guid.Data1, target_guid.Data2, target_guid.Data3,
                    target_guid.Data4[0], target_guid.Data4[1], target_guid.Data4[2], target_guid.Data4[3],
                    target_guid.Data4[4], target_guid.Data4[5], target_guid.Data4[6], target_guid.Data4[7]);

                memcpy(&_guid, (PVOID)((UINT64)channel + 0x9D8), sizeof(GUID));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: [!] Find Identify GUID of target channel {%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}\n",
                    _guid.Data1, _guid.Data2, _guid.Data3,
                    _guid.Data4[0], _guid.Data4[1], _guid.Data4[2], _guid.Data4[3],
                    _guid.Data4[4], _guid.Data4[5], _guid.Data4[6], _guid.Data4[7]);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: [!] Channel Info: STATUS:  0x%X\n", *(PVMBCHANNEL)((UINT64)channel + 0x108)); // This value is not One(1),
                                                                                                                                                  // return 0xC0000184(STATUS_INVALID_DEVICE_STATE)
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: [!] Channel Info: vmID = 0x%X\n", *(PVMBCHANNEL)((UINT64)channel + 0x64C));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: [!] Channel Info: vtlLevel = 0x%X\n", *(PVMBCHANNEL)((UINT64)channel + 0x6FA));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: [!] Channel Info: name = %S\n", *(PVMBCHANNEL)((UINT64)channel + 0x7C8));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: [!] Channel Info: isPipe = 0x%X\n", *(PVMBCHANNEL)((UINT64)channel + 0x640));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: [!] Channel Info: callbackProcessPacket = 0x%p\n", *(PVMBCHANNEL)((UINT64)channel + 0x710));
                PVOID ptr = *(VMBCHANNEL*)((UINT64)channel + 0x870);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: [!] Channel Info: Pointer = 0x%p\n",  ptr);
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: [!] Channel Info: send packet size = 0x%X\n", *(PUINT16)((UINT64)ptr + 0x70));
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "=================\n");
                
                return status;
            }
            channel = *(PVMBCHANNEL*)((UINT64)channel + vmbChannelOffset);
            if (!channel || channel == kmclChannelListLocation) {
                return status;
            }
            channel = *(PVMBCHANNEL*)((UINT64)channel - vmbChannelOffset);

        }
    }
    return status;
}

VOID EvtWdfDriverUnload(WDFDRIVER Driver)
{
    PDRIVER_OBJECT driverObject;
    PAGED_CODE();
    driverObject = WdfDriverWdmGetDriverObject(Driver);
}

NTSTATUS _pVmbPacketSend(PVOID pStorvspPkt, UINT32 storvspPktSize, PVOID pFuzzPayload, ULONG fuzzPayloadSize) {
    VMBPACKET vmbPacket = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    PMDL pMdl = NULL;

    if (!channel)
        return STATUS_INVALID_MEMBER;

    if (fuzzPayloadSize > 0)
    {
        pMdl = IoAllocateMdl(
            pFuzzPayload,
            fuzzPayloadSize,
            FALSE,
            FALSE,
            NULL
        );
        MmBuildMdlForNonPagedPool(pMdl);
    }

    vmbPacket = pVmbPacketAllocate((VMBCHANNEL)channel);
    if (!vmbPacket)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: VmbPacketAllocate was failed!\n");
        goto cleanup;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: VmbPacketAllocate succeed!\n");
    pVmbChannelEnable((VMBCHANNEL)channel);

    // backup & replace callback function
    PVOID OriginalCallbackProcessingComplete = *(VMBCHANNEL*)((UINT64)channel + 0x718);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness:  VMBChannel->callbackProcessingComplete (ORIGINAL): 0x%llX\n", OriginalCallbackProcessingComplete);  // channel->callbackProcessingComplete; 

    //((PUINT64)channel)[0x718 / sizeof(UINT64)] = (UINT64)&setPacketHandled;
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness:  VMBChannel->callbackProcessingComplete (CHANGED): 0x%llX\n", *(VMBCHANNEL*)((UINT64)channel + 0x718));  // channel->callbackProcessingComplete; 

    
    // Get channel pointer
    PVOID ptr = *(VMBCHANNEL*)((UINT64)channel + 0x870);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness:  VMBChannel->ptr: 0x%llX\n", ptr);  // channel->ptr; 

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, " ==========================\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, " [+]  Size: 0x%llX\n", *(PUINT16)((UINT64)ptr + 0x70));
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, " [+]  Original Callback: 0x%llX\n", OriginalCallbackProcessingComplete);
    if (fuzzPayloadSize > 0) {
        UINT32 MdlOffset = 0;
        UINT32 Flags = VMBUS_CHANNEL_FORMAT_FLAG_WAIT_FOR_COMPLETION | VMBUS_CHANNEL_FORMAT_FLAG_FORCE_MDL_LENGTH; // default value is 3
        /*
        if ((v26 & 0x40) != 0)
        {
            Flags = 0xB;
        }
        else if ((v26 & 0x80u) != 0)
        {
            Flags = 0x13;
        }*/
        
        status = pVmbPacketSendWithExternalMdl(vmbPacket, pStorvspPkt, storvspPktSize, pMdl, MdlOffset, fuzzPayloadSize, Flags);
    }
    else {
        status = pVmbPacketSend(vmbPacket, pStorvspPkt, storvspPktSize, NULL, 0x1);
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, " [+] VmbChannelSendSynchronousRequest() - Status: 0x%x\n", status);
cleanup:
    return status;
}

void EvtWdfIoQueueIoDeviceControl(
    WDFQUEUE Queue,
    WDFREQUEST Request,
    size_t OutputBufferLength,
    size_t InputBufferLength,
    ULONG IoControlCode
)
{
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(Queue);

    NTSTATUS status;
    PVOID requestBuf = NULL;
    ULONG requestBufSize = 0;
    PVOID pStorvspPkt = NULL;
    PVOID pFuzzPayload = NULL;
    ULONG fuzzPayloadSize = 0;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: EvtWdfIoQueueIoDeviceControl, IOCTL: 0x%x\n", IoControlCode);

    switch (IoControlCode) {
    case IOCTL_SEND_PACKET:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: EvtWdfIoQueueIoDeviceControl, IOCTL_SEND_PACKET!\n");
        break;
    default:
        break;
    }
    // Allocate pStorvspPkt
    pStorvspPkt = ExAllocatePool2(POOL_FLAG_NON_PAGED, STORVSC_PKT_SIZE, HARNESS_POOL_TAG);
    if (NULL == pStorvspPkt) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: ExAllocatePool2 failed\n");
        goto exit;
    }

    // Get payload from userleve to kernel
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Calling WdfRequestRetreiveInputBuffer\n");
    status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &requestBuf, (size_t*)&requestBufSize);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfRequestRetreiveInputBuffer Failed: %x\n", status);
        goto exit;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: InputBufSize %x, requestBufSize %x\n", InputBufferLength, requestBufSize);
    fuzzPayloadSize = requestBufSize;
    pFuzzPayload = ExAllocatePool2(POOL_FLAG_NON_PAGED, fuzzPayloadSize, HARNESS_POOL_TAG);
    if (NULL == pFuzzPayload) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: ExAllocateWithPool2 faile - pFuzzPayoadd\n");
        goto exit;
    }

    /////////////       SET SrbRequest Chunk       //////////////
    // vmstorfl!StorChannelSendSrbRequest()
    /* SAMPLE FOR  STORVSC
        * 03 00 00 00 01 00 00 00 00 00 00 00 34 00 00 00 < -- 0xc (WORD)
        * 00 00 00 00 0C 14 01 00 10 00 00 00 A0 00 00 00 < -- 0x14, 0x15, 0x16, 0x18, 0x1c
        * 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 < -- 0x25
        * 00 00 53 00 58 01 08 00 0A 00 00 00 00 00 00 00 < -- 0x32, 0x34, 0x35, 0x36, 0x38
     */
    struct vstor_packet* packet = NULL;
    packet = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(struct vstor_packet), HARNESS_POOL_TAG);
    if (packet == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: ExAllocateWithPool2 failed - SRB packet\n");
        goto exit;
    }
    packet->operation = VSTOR_OPERATION_EXECUTE_SRB;	// packet + 0x0:: 03
    packet->flags = 1;	// packet + 0x4
    packet->status = 0;	// packet + 0x8

    ((PUINT8)packet)[0xC] = 0x34;	// packet + 0xC (vmscsi_request + 0) :: vm_srb.length == 0x0034
    ((PUINT8)packet)[0xE] = 0;	// packet + 0xE (vmscsi_request + 2) :: vm_srb.srb_status
    ((PUINT8)packet)[0xF] = 0;	// packet + 0xF (vmscsi_request + 3) :: vm_srb.scsi_status 

    ((PUINT8)packet)[0x10] = 0;	// packet + 0x10 (vmscsi_request + 4) :: vm_srb.port_number 
    ((PUINT8)packet)[0x11] = 0;	// packet + 0x11 (vmscsi_request + 5) :: vm_srb.path_id < 0x100 

	// packet->vm_srb.target_id = 0x00; // 0x12 (only zero, for finding devie_object at VspAdapterFindDeviceLocked())
    ((PUINT8)packet)[0x12] = 0;	// packet + 0x12 (vmscsi_request + 6) :: vm_srb.target_id < 0x80

    // packet->vm_srb.lun = 0x00;		// 0x13 (only zero, for finding devie_object at VspAdapterFindDeviceLocked())
    ((PUINT8)packet)[0x13] = 0;	// packet + 0x13 (vmscsi_request + 7) :: vm_srb.lun < 0xFF 
                                // MDL 전달 시, VSP REQUEST TYPE이 READ_TYPE 일 경우 항상 0이어야 함

    //packet->vm_srb.cdb_length = rand() % 0x11; // <= 0x10
    ((PUINT8)packet)[0x14] = 0x10;	// packet + 0x14 (vmscsi_request + 8) :: vm_srb.cdb_length <= 0x10
    //packet->vm_srb.sense_info_length = rand() % 0x15; // <= 0x14
    ((PUINT8)packet)[0x15] = 0x14;  // packet + 0x15 (vmscsi_request + 9) ::  vm_srb.sense_info_length <= 0x14 

    ((PUINT8)packet)[0x16] = 0x01;	// packet + 0x16 (vmscsi_request + A) :: vm_srb.data_in 
    ((PUINT8)packet)[0x17] = 0x00;	// packet + 0x17 (vmscsi_request + B) :: vm_srb.reserved

    if (requestBufSize == 0) {
        packet->vm_srb.data_transfer_length = 0; //  packet + 0x18 (vmscsi_request + C) :: data_transfer_length == 0
    }
    else if (requestBufSize != 0) {
        ((PUINT8)packet)[0x18] = (requestBufSize & 0x000000ff) >> 0x0;	// packet + 0x18 (vmscsi_request + C) :: vm_srb.data_transfer_length == sizeof(mdl_buffer)
        ((PUINT8)packet)[0x19] = (requestBufSize & 0x0000ff00) >> 0x8;	// packet + 0x19 (vmscsi_request + D) :: vm_srb.data_transfer_length
        ((PUINT8)packet)[0x1a] = (requestBufSize & 0x00ff0000) >> 0x10;	// packet + 0x1A (vmscsi_request + E) :: vm_srb.data_transfer_length
        ((PUINT8)packet)[0x1b] = (requestBufSize & 0xff000000) >> 0x18;	// packet + 0x1B (vmscsi_request + F) :: vm_srb.data_transfer_length
    }

    // CDB (Command Descriptor Block)
    // reference: List of SCSI commands (https://en.wikipedia.org/wiki/SCSI_command#List_of_SCSI_commands)
    ((PUINT8)packet)[0x1c] = 0x12;      // If Fuzzer use the MDL, cdb_vlue is 0xax or 0x12 (ref: 1C0007DC7 on VspStartJob) 
                                        // VSP REQUEST TYPE using storvsp!VspGetRequestType 
										// 0xA0 : VspAdapterHandleReportLuns() - write mode :: Host -> guest 로 전달
										// 0x12 :VspHandleAbsentLun0Inquiry() && VspAdapterHandleInquiry
										// 0x8A : UNKNWON TYPE
    ((PUINT8)packet)[0x22] = 0x02;	// ??
    ((PUINT8)packet)[0x23] = 0x32;	// ??
    ((PUINT8)packet)[0x24] = 0x2d;	// ??
    ((PUINT8)packet)[0x25] = 0xa8;	// ??
    
    // Below is Unknown value..
    ((PUINT8)packet)[0x33] = 0x20;	// ??
    ((PUINT8)packet)[0x34] = 0x80;	// packet + 0x34 (vmscsi_request + 0x28) :: use `vhdparser!NVhdParserExecuteScsiRequestDisk+0xb7`
    ((PUINT8)packet)[0x35] = 0x03;	// packet + 0x35 (vmscsi_request + 0x29) :: use `vhdparser!NVhdParserExecuteScsiRequestDisk+0xb7`
    ((PUINT8)packet)[0x36] = 0x20;	// packet + 0x36 (vmscsi_request + 0x2A) :: use `vhdparser!NVhdParserExecuteScsiRequestDisk+0xb7`
    ((PUINT8)packet)[0x37] = 0x40;	// packet + 0x37 (vmscsi_request + 0x2B) :: use `vhdparser!NVhdParserExecuteScsiRequestDisk+0xb7`
    ((PUINT8)packet)[0x38] = 0x41;	// ??
    ((PUINT8)packet)[0x3c] = 0xa8;	// ??
    ((PUINT8)packet)[0x3d] = 0x2d;	// ??
    ((PUINT8)packet)[0x3e] = 0x41; //0x3e;	// ??
    ((PUINT8)packet)[0x3f] = 0x41; //0x02;	// ??
    //////////////////////////////////////////////////////////////////////////////////

    // Send SRB request from Guest to Host
    RtlCopyMemory(pFuzzPayload, requestBuf, requestBufSize);
    status = _pVmbPacketSend(packet, (UINT32)STORVSC_PKT_SIZE, pFuzzPayload, (ULONG)fuzzPayloadSize);

    // Complete the WDF Request (originated by the IOCTL)
    WdfRequestComplete(Request, STATUS_SUCCESS);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: SendPacket Failed: %x\n", status);
        goto exit;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: SendPacket Success\n");

exit:
    if (pStorvspPkt) {
        ExFreePoolWithTag(pStorvspPkt, HARNESS_POOL_TAG);
        pStorvspPkt = NULL;
    }
    if (pFuzzPayload) {
        ExFreePoolWithTag(pFuzzPayload, HARNESS_POOL_TAG);
        pFuzzPayload = NULL;
    }
}

NTSTATUS
EvtDeviceAdd(
    WDFDRIVER Driver,
    PWDFDEVICE_INIT DeviceInit
)

/*++
Routine Description:
    This routine is the AddDevice entry point for the sample device driver.
    It sets the ISR and DPC routine handlers for the interrupt and the passive
    level callback for the passive interrupt
    N.B. The sample device expects two interrupt resources in connecting its
    DIRQL ISR and PASSIVE_LEVEL callback.
Arguments:
    Driver - Supplies a handle to the driver object created in DriverEntry.
    DeviceInit - Supplies a pointer to a framework-allocated WDFDEVICE_INIT
        structure.
Return Value:
    NTSTATUS code.
--*/

{

    WDFDEVICE Device;
    WDF_OBJECT_ATTRIBUTES FdoAttributes;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG  ioQueueConfig;
    WDFQUEUE  hQueue;
    UNREFERENCED_PARAMETER(Driver);
    //
    // Initialize FDO attributes with the sample device extension.
    //

    WDF_OBJECT_ATTRIBUTES_INIT(&FdoAttributes);

    //
    // Call the framework to create the device and attach it to the lower stack.
    //

    status = WdfDeviceInitAssignName(DeviceInit, &ntDeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceInitAssignName Failed: %x\n", status);
        goto EvtDeviceAddEnd;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceInitAssignName succeed\n");

    status = WdfDeviceInitAssignSDDLString(DeviceInit, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_R_RES_R);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceInitAssignSDDLString Failed: %x\n", status);
        goto EvtDeviceAddEnd;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceInitAssignSDDLString succeed\n");

    status = WdfDeviceCreate(&DeviceInit, &FdoAttributes, &Device);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceCreate Failed: %x\n", status);
        goto EvtDeviceAddEnd;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceCreate succeed\n");

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &ioQueueConfig,
        WdfIoQueueDispatchSequential
    );

    ioQueueConfig.EvtIoDeviceControl = EvtWdfIoQueueIoDeviceControl;


    status = WdfIoQueueCreate(
        Device,
        &ioQueueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &hQueue
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfIoQueueCreate Failed: %x\n", status);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfIoQueueCreate succeed\n");

    status = WdfDeviceCreateSymbolicLink(Device, &dosDeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceCreateSymbolicLink Failed: %x\n", status);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDeviceCreateSymbolicLink succeed\n");

EvtDeviceAddEnd:
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;

    UNICODE_STRING vmbkclModuleName;
    UNICODE_STRING storvscModuleName;

    CHAR vmbPacketAllocate[] = "VmbPacketAllocate";
    CHAR vmbPacketSend[] = "VmbPacketSend";
    CHAR vmbPacketSendWithExternalMdl[] = "VmbPacketSendWithExternalMdl";
    CHAR vmbChannelSendSynchronousRequest[] = "VmbChannelSendSynchronousRequest";
    CHAR vmbPacketFree[] = "VmbPacketFree";
    CHAR vmbPacketSetCompletionRoutine[] = "VmbPacketSetCompletionRoutine";
    CHAR vmbChannelEnable[] = "VmbChannelEnable";

    WDF_DRIVER_CONFIG config;

    WDF_DRIVER_CONFIG_INIT(&config,
        EvtDeviceAdd
    );
    config.EvtDriverUnload = EvtWdfDriverUnload;

    status = WdfDriverCreate(DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDriverCreate failed: 0x%x\n", status);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: WdfDriverCreate succeed\n");
    
    //////// TEST FOR Storage by bk ////////////////////
    RtlInitUnicodeString(&storvscModuleName, storvscModulePath);
    status = GetModuleAddress(&storvscModuleName, &StorvscBaseAddress);
    if (!NT_SUCCESS(status) || StorvscBaseAddress == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: STORVSC Address was not found\n");
        return status;
    }
    /////////////////////////////////////////////////////

    RtlInitUnicodeString(&vmbkclModuleName, vmbkclModulePath);
    status = GetModuleAddress(&vmbkclModuleName, &vmbkclBaseAddress);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: vmbkcl Address was not found\n");
        return status;
    }

    // Find FUnctions for send packet
    pVmbPacketAllocate = (PFN_VMB_PACKET_ALLOCATE)KernelGetProcAddress(vmbkclBaseAddress, (PCHAR)&vmbPacketAllocate);
    pVmbPacketSend = (PFN_VMB_PACKET_SEND)KernelGetProcAddress(vmbkclBaseAddress, (PCHAR)&vmbPacketSend);
    pVmbPacketFree = (PFN_VMB_PACKET_FREE)KernelGetProcAddress(vmbkclBaseAddress, (PCHAR)&vmbPacketFree);
    pVmbPacketSetCompletionRoutine = (PFN_VMB_PACKET_SET_COMPLETION_ROUTINE)KernelGetProcAddress(vmbkclBaseAddress, (PCHAR)&vmbPacketSetCompletionRoutine);
    pVmbChannelEnable = (PFN_VMB_CHANNEL_ENABLE)KernelGetProcAddress(vmbkclBaseAddress, (PCHAR)&vmbChannelEnable);

    pVmbChannelSendSynchronousRequest = (PFN_VMB_CHANNEL_SEND_SYNCHRONOUS_REQUEST)KernelGetProcAddress(vmbkclBaseAddress, (PCHAR)&vmbChannelSendSynchronousRequest);
    pVmbPacketSendWithExternalMdl = (PFN_VMB_PACKET_SEND_WITH_EXTERNAL_MDL)KernelGetProcAddress(vmbkclBaseAddress, (PCHAR)&vmbPacketSendWithExternalMdl);


    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: VmbPacketAllocate Address: %p\n", pVmbPacketAllocate);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: VmbPacketSend Address: %p\n", pVmbPacketSend);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: VmbPacketFree Address: %p\n", pVmbPacketFree);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: pVmbPacketSetCompletionRoutine Address: %p\n", pVmbPacketSetCompletionRoutine);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: pVmbChannelEnable Address: %p\n", pVmbChannelEnable);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: pVmbChannelSendSynchronousRequest Address: %p\n", pVmbChannelSendSynchronousRequest);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: VmbPacketSendWithExternalMdl Address: %p\n", pVmbPacketSendWithExternalMdl);


    if (NULL == pVmbPacketAllocate || NULL == pVmbPacketSend || NULL == pVmbChannelSendSynchronousRequest || NULL == pVmbPacketFree || NULL == pVmbPacketSetCompletionRoutine) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: KernelGetProcAddress was failed!\n");
    }

    // Find Miniport (storvsc.sys or vmstorfl.sys)
    status = FindOurMiniportChannel();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Failed to find the address of netvsc's VMBChannel\n");
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "CPHarness: Miniport Channel: %p\n", channel);

    return status;
}
