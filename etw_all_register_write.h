typedef unsigned char UCHAR;
typedef short WCHAR;
typedef unsigned short USHORT;
typedef unsigned int DWORD;
typedef long LONG;
typedef unsigned long ULONG;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef unsigned long long ULONG64;
typedef unsigned long long GUID;

typedef void * PVOID;
typedef UCHAR BOOLEAN;
typedef GUID * LPCGUID;
typedef WCHAR * PCWSTR;

typedef PVOID HANDLE;
typedef ULONGLONG REGHANDLE;
typedef REGHANDLE * PREGHANDLE;
typedef ULONG64 TRACEHANDLE;

typedef int ETW_NOTIFICATION_TYPE;

typedef union _LARGE_INTEGER {
  struct {
    DWORD LowPart;
    LONG  HighPart;
  } DUMMYSTRUCTNAME;
  struct {
    DWORD LowPart;
    LONG  HighPart;
  } u;
  LONGLONG QuadPart;
} LARGE_INTEGER;

typedef struct _EVENT_FILTER_DESCRIPTOR {
    ULONGLONG Ptr;
    ULONG Size;
    ULONG Type;
} *PEVENT_FILTER_DESCRIPTOR;

typedef struct _EVENT_DATA_DESCRIPTOR {
    ULONGLONG Ptr;
    ULONG Size;
    ULONG Reserved;
} *PEVENT_DATA_DESCRIPTOR;


typedef struct _EVENT_DESCRIPTOR {
    USHORT Id;
    UCHAR Version;
    UCHAR Channel;
    UCHAR Level;
    UCHAR Opcode;
    USHORT Task;
    ULONGLONG Keyword;
} *PCEVENT_DESCRIPTOR;

typedef struct _EVENT_TRACE_HEADER {
  USHORT        Size;
  union {
    USHORT FieldTypeFlags;
    struct {
      UCHAR HeaderType;
      UCHAR MarkerFlags;
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
  union {
    ULONG Version;
    struct {
      UCHAR  Type;
      UCHAR  Level;
      USHORT Version;
    } Class;
  } DUMMYUNIONNAME2;
  ULONG         ThreadId;
  ULONG         ProcessId;
  LARGE_INTEGER TimeStamp;
  union {
    GUID      Guid;
    ULONGLONG GuidPtr;
  } DUMMYUNIONNAME3;
  union {
    struct {
      ULONG KernelTime;
      ULONG UserTime;
    } DUMMYSTRUCTNAME;
    ULONG64 ProcessorTime;
    struct {
      ULONG ClientContext;
      ULONG Flags;
    } DUMMYSTRUCTNAME2;
  } DUMMYUNIONNAME4;
} EVENT_TRACE_HEADER, *PEVENT_TRACE_HEADER;

typedef struct _EVENT_INSTANCE_HEADER {
  USHORT        Size;
  union {
    USHORT FieldTypeFlags;
    struct {
      UCHAR HeaderType;
      UCHAR MarkerFlags;
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME;
  union {
    ULONG Version;
    struct {
      UCHAR  Type;
      UCHAR  Level;
      USHORT Version;
    } Class;
  } DUMMYUNIONNAME2;
  ULONG         ThreadId;
  ULONG         ProcessId;
  LARGE_INTEGER TimeStamp;
  ULONGLONG     RegHandle;
  ULONG         InstanceId;
  ULONG         ParentInstanceId;
  union {
    struct {
      ULONG KernelTime;
      ULONG UserTime;
    } DUMMYSTRUCTNAME;
    ULONG64 ProcessorTime;
    struct {
      ULONG EventId;
      ULONG Flags;
    } DUMMYSTRUCTNAME2;
  } DUMMYUNIONNAME3;
  ULONGLONG     ParentRegHandle;
} EVENT_INSTANCE_HEADER, *PEVENT_INSTANCE_HEADER;

typedef struct _EVENT_INSTANCE_INFO {
  HANDLE RegHandle;
  ULONG  InstanceId;
} EVENT_INSTANCE_INFO, *PEVENT_INSTANCE_INFO;

typedef struct _ETW_NOTIFICATION_HEADER {
  ETW_NOTIFICATION_TYPE NotificationType;
  ULONG NotificationSize;
  ULONG Offset;
  BOOLEAN ReplyRequested;
  ULONG Timeout;
  union {
    ULONG ReplyCount;
    ULONG NotifyeeCount;
  } DUMMYUNIONNAME;
  ULONGLONG Reserved2;
  ULONG TargetPID;
  ULONG SourcePID;
  GUID DestinationGuid;
  GUID SourceGuid;
} ETW_NOTIFICATION_HEADER, *PETW_NOTIFICATION_HEADER;

typedef void (* PENABLECALLBACK) (LPCGUID, ULONG, UCHAR, ULONGLONG, ULONGLONG, PEVENT_FILTER_DESCRIPTOR, PVOID);
typedef ULONG (*PETW_NOTIFICATION_CALLBACK) (PETW_NOTIFICATION_HEADER, PVOID );

# Modern ETW API

ULONG EtwRegister(LPCGUID ProviderId, PENABLECALLBACK EnableCallback, PVOID CallbackContext, PREGHANDLE RegHandle);
ULONG EventRegister   (LPCGUID ProviderId, PENABLECALLBACK EnableCallback, PVOID CallbackContext, PREGHANDLE RegHandle);
ULONG EtwEventRegister(LPCGUID ProviderId, PENABLECALLBACK EnableCallback, PVOID CallbackContext, PREGHANDLE RegHandle);

ULONG EtwNotificationRegister     (LPCGUID Guid, ULONG Type, PETW_NOTIFICATION_CALLBACK Callback, PVOID Context, REGHANDLE *RegHandle);
ULONG EventNotificationRegister   (LPCGUID Guid, ULONG Type, PETW_NOTIFICATION_CALLBACK Callback, PVOID Context, REGHANDLE *RegHandle);
ULONG EtwEventNotificationRegister(LPCGUID Guid, ULONG Type, PETW_NOTIFICATION_CALLBACK Callback, PVOID Context, REGHANDLE *RegHandle);

ULONG EtwWrite     (REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
ULONG EventWrite   (REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
ULONG EtwEventWrite(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);

ULONG EtwWriteEx     (REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, ULONG64 Filter, ULONG Flags, LPCGUID ActivityId, LPCGUID RelatedActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
ULONG EventWriteEx   (REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, ULONG64 Filter, ULONG Flags, LPCGUID ActivityId, LPCGUID RelatedActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
ULONG EtwEventWriteEx(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, ULONG64 Filter, ULONG Flags, LPCGUID ActivityId, LPCGUID RelatedActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);

ULONG EtwWriteTransfer     (REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, LPCGUID RelatedActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
ULONG EventWriteTransfer   (REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, LPCGUID RelatedActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
ULONG EtwEventWriteTransfer(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, LPCGUID RelatedActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);

ULONG EtwEventWriteFull    (REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, USHORT EventProperty, LPCGUID ActivityId, LPCGUID RelatedActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);

ULONG EtwWriteStartScenario     (REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
ULONG EventWriteStartScenario   (REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
ULONG EtwEventWriteStartScenario(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);

ULONG EtwWriteEndScenario     (REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
ULONG EventWriteEndScenario   (REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
ULONG EtwEventWriteEndScenario(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);

ULONG EtwWriteString     (REGHANDLE RegHandle, UCHAR Level, ULONGLONG Keyword, PCWSTR String);
ULONG EventWriteString   (REGHANDLE RegHandle, UCHAR Level, ULONGLONG Keyword, PCWSTR String);
ULONG EtwEventWriteString(REGHANDLE RegHandle, UCHAR Level, ULONGLONG Keyword, PCWSTR String);

ULONG EtwWriteNoRegistration     (LPCGUID ProviderId, PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
ULONG EventWriteNoRegistration   (LPCGUID ProviderId, PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);
ULONG EtwEventWriteNoRegistration(LPCGUID ProviderId, PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData);

# Legacy ETW API

ULONG TraceMessage   (TRACEHANDLE LoggerHandle, ULONG MessageFlags, LPCGUID MessageGuid, USHORT MessageNumber, ...);
ULONG EtwTraceMessage(TRACEHANDLE LoggerHandle, ULONG MessageFlags, LPCGUID MessageGuid, USHORT MessageNumber, ...);

ULONG TraceMessageVa   (TRACEHANDLE LoggerHandle, ULONG MessageFlags, LPCGUID MessageGuid, USHORT MessageNumber, va_list MessageArgList);
ULONG EtwTraceMessageVa(TRACEHANDLE LoggerHandle, ULONG MessageFlags, LPCGUID MessageGuid, USHORT MessageNumber, va_list MessageArgList);

ULONG TraceEvent      (TRACEHANDLE TraceHandle, PEVENT_TRACE_HEADER EventTrace);
ULONG EtwTraceEvent   (TRACEHANDLE TraceHandle, PEVENT_TRACE_HEADER EventTrace);
ULONG EtwLogTraceEvent(TRACEHANDLE TraceHandle, PEVENT_TRACE_HEADER EventTrace);

ULONG TraceEventInstance   (TRACEHANDLE TraceHandle, PEVENT_INSTANCE_HEADER EventTrace, PEVENT_INSTANCE_INFO InstInfo, PEVENT_INSTANCE_INFO ParentInstInfo);
ULONG EtwTraceEventInstance(TRACEHANDLE TraceHandle, PEVENT_INSTANCE_HEADER EventTrace, PEVENT_INSTANCE_INFO InstInfo, PEVENT_INSTANCE_INFO ParentInstInfo);
