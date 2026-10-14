%define AF_INET              2
%define SOCK_STREAM          1
%define IPPROTO_TCP          6
%define INVALID_SOCKET       -1
%define SOCKET_ERROR         -1
%define STD_OUTPUT_HANDLE    -11
%define SOL_SOCKET           0xffff
%define SO_REUSEADDR         4
%define SO_RCVTIMEO           0x1006
%define GENERIC_READ          0x80000000
%define GENERIC_WRITE         0x40000000
%define FILE_SHARE_READ       1
%define FILE_SHARE_WRITE      2
%define OPEN_EXISTING         3
%define OPEN_ALWAYS           4
%define FILE_ATTRIBUTE_NORMAL 0x80
%define FILE_END              2
%define INVALID_HANDLE        -1
%define WAIT_OBJECT_0         0
%define BCRYPT_USE_SYSTEM_PREFERRED_RNG 2

%define MAX_ACCOUNTS          128
%define MAX_SESSIONS          512

%define ACC_ID                0
%define ACC_NAME              16
%define ACC_SALT              48
%define ACC_HASH              64
%define ACC_FLAGS             96
%define ACC_CREATED           104
%define ACCOUNT_SIZE          112

%define SES_ACCESS            0
%define SES_REFRESH           32
%define SES_ACCOUNT           64
%define SES_CLIENT            80
%define SES_ACCESS_EXP        112
%define SES_REFRESH_EXP       120
%define SESSION_SIZE          128

%define DEFAULT_PORT         8080
%define REQUEST_CAP          65536
%define RESPONSE_CAP         16384

; request_info layout passed between parser and router.
%define INFO_METHOD          0       ; dword: 1 GET, 2 POST, 3 PUT, 4 DELETE
%define INFO_PATH            8       ; qword: path inside request buffer
%define INFO_PATH_LEN        16      ; dword: path length without query string
%define INFO_BODY_LEN        20      ; dword: Content-Length
%define INFO_HEADER_END      24      ; dword: first byte after CRLFCRLF
%define INFO_BODY            32      ; qword: request body
%define INFO_QUERY           40      ; qword: query string without '?'
%define INFO_QUERY_LEN       48      ; dword: query string length
%define INFO_REQUEST         56      ; qword: complete request buffer
%define INFO_SIZE            64
%define WORK_SIZE            (REQUEST_CAP + RESPONSE_CAP + INFO_SIZE)

extern WSAStartup
extern WSAGetLastError
extern WSACleanup
extern socket
extern bind
extern listen
extern accept
extern recv
extern send
extern setsockopt
extern closesocket
extern CreateThread
extern CloseHandle
extern GetProcessHeap
extern HeapAlloc
extern HeapFree
extern GetStdHandle
extern ExitProcess
extern BCryptGenRandom
extern BCryptOpenAlgorithmProvider
extern BCryptCloseAlgorithmProvider
extern BCryptCreateHash
extern BCryptHashData
extern BCryptFinishHash
extern BCryptDestroyHash
extern CreateMutexA
extern WaitForSingleObject
extern ReleaseMutex
extern CreateDirectoryA
extern CreateFileA
extern GetFileSize
extern ReadFile
extern WriteFile
extern SetFilePointer
extern FlushFileBuffers
extern GetSystemTimeAsFileTime
extern FileTimeToSystemTime
