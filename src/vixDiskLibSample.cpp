/* *************************************************
 * Copyright 2007-2015 VMware, Inc.  All rights reserved. -- VMware Confidential
 * *************************************************/

/*
 * vixDiskLibSample.cpp --
 *
 *      Sample program to demonstrate usage of vixDiskLib DLL.
 */

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#include <process.h>
#else
#include <dlfcn.h>
#include <sys/time.h>
#endif

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <list>
#include <memory>
#include <sstream>
#include <fstream>
#include <vector>

#ifdef _MSC_VER
#define USE_CXX11 (_MSC_VER > 1700)
#else
#define USE_CXX11 (__cplusplus > 199711L)
#endif

#if !USE_CXX11
#include <boost/asio.hpp>
#include <boost/thread/thread.hpp>
#include <boost/make_shared.hpp>
#endif

#include "vixDiskLib.h"

#ifdef FOR_MNTAPI
#ifndef _WIN32
#include <tr1/memory>
#endif
#include "vixMntapi.h"
using std::tr1::shared_ptr;
#endif

using namespace std;
using std::cin;
using std::cout;
using std::string;
using std::endl;
using std::vector;

#define COMMAND_CREATE          (1 << 0)
#define COMMAND_DUMP            (1 << 1)
#define COMMAND_FILL            (1 << 2)
#define COMMAND_INFO            (1 << 3)
#define COMMAND_REDO            (1 << 4)
#define COMMAND_DUMP_META       (1 << 5)
#define COMMAND_READ_META       (1 << 6)
#define COMMAND_WRITE_META      (1 << 7)
#define COMMAND_MULTITHREAD     (1 << 8)
#define COMMAND_CLONE           (1 << 9)
#define COMMAND_READBENCH       (1 << 10)
#define COMMAND_WRITEBENCH      (1 << 11)
#define COMMAND_CHECKREPAIR     (1 << 12)
#define COMMAND_READASYNCBENCH       (1 << 13)
#define COMMAND_WRITEASYNCBENCH      (1 << 14)
#define COMMAND_GET_ALLOCATED_BLOCKS (1 << 15)
#define COMMAND_REPLACE              (1 << 16)
#define COMMAND_RECORDCBT            (1 << 17)
#define COMMAND_RECOVERCBT           (1 << 18)

#define VIXDISKLIB_VERSION_MAJOR 6
#define VIXDISKLIB_VERSION_MINOR 5

// Default buffer size (in sectors) for read/write benchmarks
#define DEFAULT_BUFSIZE 128

// Print updated statistics for read/write benchmarks roughly every
// BUFS_PER_STAT sectors (current value is 64MBytes worth of data)
#define BUFS_PER_STAT (128 * 1024)

// Character array for randonm filename generation
static const char randChars[] = "0123456789"
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// Per-thread information for multi-threaded VixDiskLib test.
struct ThreadData {
   std::string dstDisk;
   VixDiskLibHandle srcHandle;
   VixDiskLibHandle dstHandle;
   VixDiskLibSectorType numSectors;
};


static struct {
    int command;
    VixDiskLibAdapterType adapterType;
    char *transportModes;
    vector<string> diskPaths;
    char *parentPath;
    char *metaKey;
    char *metaVal;
    int filler;
    unsigned mbSize;
    VixDiskLibSectorType numSectors;
    VixDiskLibSectorType startSector;
    VixDiskLibSectorType bufSize;
    VixDiskLibSectorType chunkSize;
    uint32 openFlags;
    unsigned numThreads;
    Bool success;
    Bool isRemote;
    char *host;
    char *userName;
    char *password;
    char *cookie;
    char *thumbPrint;
    char *vimApiVer;
    int port;
    int nfcHostPort;
    char *srcPath;
    VixDiskLibConnection connection;
    char *vmxSpec;
    char *fcdid;
    char *fcdds;
    bool useInitEx;
    char *cfgFile;
    char *libdir;
    char *ssMoRef;
    int repair;
} appGlobals;

static vector<string> split(const  std::string& s, const std::string& delim);
static bool replace(uint8 *buf, int length, string source, string dest);
static int ParseArguments(int argc, char* argv[]);
static void DoCreate(void);
static void DoRedo(void);
static void DoFill(void);
static void DoDump(void);
static void DoReadMetadata(void);
static void DoWriteMetadata(void);
static void DoDumpMetadata(void);
static void DoInfo(void);
static void DoReplace(void);
static void DoRecordCBT(void);
static void DoRecoverCBT(void);
static void DoTestMultiThread(void);
static void DoClone(void);
static int BitCount(int number);
static void DumpBytes(const uint8 *buf, size_t n, int step);
static void DoRWBench(bool read, bool async);
static void DoCheckRepair(Bool repair);
static void DoAsyncIO(bool read);
#ifdef FOR_MNTAPI
static void DoMntApi(VixDiskLibConnection connection, const char* disk, uint32 openFlags);
#endif
static void DoGetAllocatedBlocks(void);


#define THROW_ERROR(vixError) \
   throw VixDiskLibErrWrapper((vixError), __FILE__, __LINE__)

#define CHECK_AND_THROW_2(vixError, buf)                             \
   do {                                                              \
      if (VIX_FAILED((vixError))) {                                  \
         delete[] buf;                                               \
         throw VixDiskLibErrWrapper((vixError), __FILE__, __LINE__); \
      }                                                              \
   } while (0)

#define CHECK_AND_THROW(vixError) CHECK_AND_THROW_2(vixError, ((int*)0))

#ifdef DYNAMIC_LOADING

static VixError
(*VixDiskLib_InitEx_Ptr)(uint32 majorVersion,
                         uint32 minorVersion,
                         VixDiskLibGenericLogFunc *log,
                         VixDiskLibGenericLogFunc *warn,
                         VixDiskLibGenericLogFunc *panic,
                         const char* libDir,
                         const char* configFile);

static VixError
(*VixDiskLib_Init_Ptr)(uint32 majorVersion,
                       uint32 minorVersion,
                       VixDiskLibGenericLogFunc *log,
                       VixDiskLibGenericLogFunc *warn,
                       VixDiskLibGenericLogFunc *panic,
                       const char* libDir);

static void
(*VixDiskLib_Exit_Ptr)(void);

static const char *
(*VixDiskLib_ListTransportModes_Ptr)(void);


static VixError
(*VixDiskLib_Cleanup_Ptr)(const VixDiskLibConnectParams *connectParams,
                          uint32 *numCleanedUp, uint32 *numRemaining);

static VixError
(*VixDiskLib_Connect_Ptr)(const VixDiskLibConnectParams *connectParams,
                          VixDiskLibConnection *connection);

static VixError
(*VixDiskLib_ConnectEx_Ptr)(const VixDiskLibConnectParams *connectParams,
                            Bool readOnly,
                            const char *snapshotRef,
                            const char *transportModes,
                            VixDiskLibConnection *connection);

static VixError
(*VixDiskLib_Disconnect_Ptr)(VixDiskLibConnection connection);

static VixError
(*VixDiskLib_Create_Ptr)(const VixDiskLibConnection connection,
                         const char *path,
                         const VixDiskLibCreateParams *createParams,
                         VixDiskLibProgressFunc progressFunc,
                         void *progressCallbackData);

static VixError
(*VixDiskLib_CreateChild_Ptr)(VixDiskLibHandle diskHandle,
                              const char *childPath,
                              VixDiskLibDiskType diskType,
                              VixDiskLibProgressFunc progressFunc,
                              void *progressCallbackData);

static VixError
(*VixDiskLib_Open_Ptr)(const VixDiskLibConnection connection,
                       const char *path,
                       uint32 flags,
                       VixDiskLibHandle *diskHandle);

static VixError
(*VixDiskLib_GetInfo_Ptr)(VixDiskLibHandle diskHandle,
                          VixDiskLibInfo **info);

static void
(*VixDiskLib_FreeInfo_Ptr)(VixDiskLibInfo *info);


static const char *
(*VixDiskLib_GetTransportMode_Ptr)(VixDiskLibHandle diskHandle);

static VixError
(*VixDiskLib_Close_Ptr)(VixDiskLibHandle diskHandle);

static VixError
(*VixDiskLib_Read_Ptr)(VixDiskLibHandle diskHandle,
                       VixDiskLibSectorType startSector,
                       VixDiskLibSectorType numSectors,
                       uint8 *readBuffer);

static VixError
(*VixDiskLib_Write_Ptr)(VixDiskLibHandle diskHandle,
                        VixDiskLibSectorType startSector,
                        VixDiskLibSectorType numSectors,
                        const uint8 *writeBuffer);

static VixError
(*VixDiskLib_ReadMetadata_Ptr)(VixDiskLibHandle diskHandle,
                               const char *key,
                               char *buf,
                               size_t bufLen,
                               size_t *requiredLen);

static VixError
(*VixDiskLib_WriteMetadata_Ptr)(VixDiskLibHandle diskHandle,
                                const char *key,
                                const char *val);

static VixError
(*VixDiskLib_GetMetadataKeys_Ptr)(VixDiskLibHandle diskHandle,
                                  char *keys,
                                  size_t maxLen,
                                  size_t *requiredLen);

static VixError
(*VixDiskLib_Unlink_Ptr)(VixDiskLibConnection connection,
                         const char *path);

static VixError
(*VixDiskLib_Grow_Ptr)(VixDiskLibConnection connection,
                       const char *path,
                       VixDiskLibSectorType capacity,
                       Bool updateGeometry,
                       VixDiskLibProgressFunc progressFunc,
                       void *progressCallbackData);
static VixError
(*VixDiskLib_Shrink_Ptr)(VixDiskLibHandle diskHandle,
                         VixDiskLibProgressFunc progressFunc,
                         void *progressCallbackData);

static VixError
(*VixDiskLib_Defragment_Ptr)(VixDiskLibHandle diskHandle,
                             VixDiskLibProgressFunc progressFunc,
                             void *progressCallbackData);

static VixError
(*VixDiskLib_Rename_Ptr)(const char *srcFileName,
                         const char *dstFileName);

static VixError
(*VixDiskLib_Clone_Ptr)(const VixDiskLibConnection dstConnection,
                        const char *dstPath,
                        const VixDiskLibConnection srcConnection,
                        const char *srcPath,
                        const VixDiskLibCreateParams *vixCreateParams,
                        VixDiskLibProgressFunc progressFunc,
                        void *progressCallbackData,
                        Bool overWrite);

static char *
(*VixDiskLib_GetErrorText_Ptr)(VixError err, const char *locale);

static void
(*VixDiskLib_FreeErrorText_Ptr)(char* errMsg);

static VixError
(*VixDiskLib_Attach_Ptr)(VixDiskLibHandle parent, VixDiskLibHandle child);

static VixError
(*VixDiskLib_SpaceNeededForClone_Ptr)(VixDiskLibHandle diskHandle,
                                      VixDiskLibDiskType cloneDiskType,
                                      uint64* spaceNeeded);

static VixError
(*VixDiskLib_CheckRepair_Ptr)(const VixDiskLibConnection connection,
                              const char *filename,
                              Bool repair);

static VixError
(*VixDiskLib_QueryAllocatedBlocks_Ptr)(VixDiskLibHandle diskHandle,
                                       VixDiskLibSectorType startSector,
                                       VixDiskLibSectorType numSectors,
                                       VixDiskLibSectorType chunkSize,
                                       VixDiskLibBlockList **blockList);



/*
 *----------------------------------------------------------------------
 *
 * LoadOneFunc --
 *
 *      Loads a single vixDiskLib function from shared library / DLL.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

#ifdef _WIN32
static void
LoadOneFunc(HINSTANCE hInstLib, void** pFunction, const char* funcName)
{
   std::stringstream strStream;
   *pFunction = GetProcAddress(hInstLib, funcName);
   if (*pFunction == NULL) {
      strStream << "Failed to load " << funcName << ". Error = " <<
         GetLastError() << "\n";
      throw std::runtime_error(strStream.str().c_str());
   }
}
#else
static void
LoadOneFunc(void* dlHandle, void** pFunction, const char* funcName)
{
   std::stringstream strStream;
   *pFunction = dlsym(dlHandle, funcName);
   char* dlErrStr = dlerror();
   if (*pFunction == NULL || dlErrStr != NULL) {
      strStream << "Failed to load " << funcName << ". Error = " <<
         dlErrStr << "\n";
      throw std::runtime_error(strStream.str().c_str());
   }
}
#endif

#define LOAD_ONE_FUNC(handle, funcName)  \
   LoadOneFunc(handle, (void**)&(funcName##_Ptr), #funcName)

#ifdef _WIN32
#define IS_HANDLE_INVALID(handle) ((handle) == INVALID_HANDLE_VALUE)
#else
#define IS_HANDLE_INVALID(handle) ((handle) == NULL)
#endif


/*
 *----------------------------------------------------------------------
 *
 * DynLoadDiskLib --
 *
 *      Dynamically loads VixDiskLib and bind to the functions.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
DynLoadDiskLib(void)
{
#ifdef _WIN32
   HINSTANCE hInstLib = LoadLibrary("vixDiskLib.dll");
#else
   void* hInstLib = dlopen("libvixDiskLib.so", RTLD_LAZY);
#endif

   // If the handle is valid, try to get the function address.
   if (IS_HANDLE_INVALID(hInstLib)) {
      cout << "Can't load vixDiskLib shared library / DLL : lasterror = " <<
#ifdef _WIN32
         GetLastError() <<
#else
         dlerror() <<
#endif
         "\n";

      exit(EXIT_FAILURE);
   }
   try {
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_InitEx);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Init);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Exit);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_ListTransportModes);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Cleanup);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Connect);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_ConnectEx);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Disconnect);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Create);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_CreateChild);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Open);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_GetInfo);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_FreeInfo);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_GetTransportMode);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Close);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Read);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Write);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_ReadMetadata);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_WriteMetadata);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_GetMetadataKeys);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Unlink);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Grow);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Shrink);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Defragment);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Rename);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Clone);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_GetErrorText);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_FreeErrorText);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_Attach);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_SpaceNeededForClone);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_CheckRepair);
      LOAD_ONE_FUNC(hInstLib, VixDiskLib_QueryAllocatedBlocks);
   } catch (const std::runtime_error& exc) {
      cout << "Error while dynamically loading : " << exc.what() << "\n";
      exit(EXIT_FAILURE);
   }
}


#define VixDiskLib_InitEx           (*VixDiskLib_InitEx_Ptr)
#define VixDiskLib_Init             (*VixDiskLib_Init_Ptr)
#define VixDiskLib_Exit             (*VixDiskLib_Exit_Ptr)
#define VixDiskLib_ListTransportModes   (*VixDiskLib_ListTransportModes_Ptr)
#define VixDiskLib_Cleanup          (*VixDiskLib_Cleanup_Ptr)
#define VixDiskLib_Connect          (*VixDiskLib_Connect_Ptr)
#define VixDiskLib_ConnectEx        (*VixDiskLib_ConnectEx_Ptr)
#define VixDiskLib_Disconnect       (*VixDiskLib_Disconnect_Ptr)
#define VixDiskLib_Create           (*VixDiskLib_Create_Ptr)
#define VixDiskLib_CreateChild      (*VixDiskLib_CreateChild_Ptr)
#define VixDiskLib_Open             (*VixDiskLib_Open_Ptr)
#define VixDiskLib_GetInfo          (*VixDiskLib_GetInfo_Ptr)
#define VixDiskLib_FreeInfo         (*VixDiskLib_FreeInfo_Ptr)
#define VixDiskLib_GetTransportMode (*VixDiskLib_GetTransportMode_Ptr)
#define VixDiskLib_Close            (*VixDiskLib_Close_Ptr)
#define VixDiskLib_Read             (*VixDiskLib_Read_Ptr)
#define VixDiskLib_Write            (*VixDiskLib_Write_Ptr)
#define VixDiskLib_ReadMetadata     (*VixDiskLib_ReadMetadata_Ptr)
#define VixDiskLib_WriteMetadata    (*VixDiskLib_WriteMetadata_Ptr)
#define VixDiskLib_GetMetadataKeys  (*VixDiskLib_GetMetadataKeys_Ptr)
#define VixDiskLib_Unlink           (*VixDiskLib_Unlink_Ptr)
#define VixDiskLib_Grow             (*VixDiskLib_Grow_Ptr)
#define VixDiskLib_Shrink           (*VixDiskLib_Shrink_Ptr)
#define VixDiskLib_Defragment       (*VixDiskLib_Defragment_Ptr)
#define VixDiskLib_Rename           (*VixDiskLib_Rename_Ptr)
#define VixDiskLib_Clone            (*VixDiskLib_Clone_Ptr)
#define VixDiskLib_GetErrorText     (*VixDiskLib_GetErrorText_Ptr)
#define VixDiskLib_FreeErrorText    (*VixDiskLib_FreeErrorText_Ptr)
#define VixDiskLib_Attach           (*VixDiskLib_Attach_Ptr)
#define VixDiskLib_SpaceNeededForClone   (*VixDiskLib_SpaceNeededForClone_Ptr)
#define VixDiskLib_CheckRepair      (*VixDiskLib_CheckRepair_Ptr)
#define VixDiskLib_QueryAllocatedBlocks  (*VixDiskLib_QueryAllocatedBlocks_Ptr)

#endif // DYNAMIC_LOADING


/*
 *----------------------------------------------------------------------
 *
 * GenerateRandomFilename --
 *
 *      Generate and return a random filename.
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
static void
GenerateRandomFilename(const string& prefix, string& randomFilename)
{
    string retStr;
    int strLen = sizeof(randChars) - 1;

    for (unsigned int i = 0; i < 8; i++)
    {
        retStr += randChars[rand() % strLen];
    }
    randomFilename = prefix + retStr;
}


#ifdef _WIN32

/*
 *----------------------------------------------------------------------
 *
 * gettimeofday --
 *
 *      Mimics BSD style gettimeofday in a way that is close enough
 *      for some I/O benchmarking.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
gettimeofday(struct timeval *tv,
             void *)
{
   uint64 ticks = GetTickCount();

   tv->tv_sec = ticks / 1000;
   tv->tv_usec = 1000 * (ticks % 1000);
}

#endif

static void
PrintStat(bool read,            // IN
          struct timeval start, // IN
          struct timeval end,   // IN
          uint32 numSectors,    // IN
          uint32 sectorSize,    // IN
          const char* prefix);  // IN

static void
InitBuffer(uint32 *buf,     // OUT
           uint32 numElems);// IN



/*
 *--------------------------------------------------------------------------
 *
 * LogFunc --
 *
 *      Callback for VixDiskLib Log messages.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
LogFunc(const char *fmt, va_list args)
{
   printf("Log: ");
   vprintf(fmt, args);
}


/*
 *--------------------------------------------------------------------------
 *
 * WarnFunc --
 *
 *      Callback for VixDiskLib Warning messages.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
WarnFunc(const char *fmt, va_list args)
{
   printf("Warning: ");
   vprintf(fmt, args);
}


/*
 *--------------------------------------------------------------------------
 *
 * PanicFunc --
 *
 *      Callback for VixDiskLib Panic messages.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
PanicFunc(const char *fmt, va_list args)
{
   printf("Panic: ");
   vprintf(fmt, args);
   exit(10);
}

typedef void (VixDiskLibGenericLogFunc)(const char *fmt, va_list args);


// Wrapper class for VixDiskLib disk objects.

class VixDiskLibErrWrapper
{
public:
    explicit VixDiskLibErrWrapper(VixError errCode, const char* file, int line)
          :
          _errCode(errCode),
          _file(file),
          _line(line)
    {
        char* msg = VixDiskLib_GetErrorText(errCode, NULL);
        _desc = msg;
        VixDiskLib_FreeErrorText(msg);
    }

    VixDiskLibErrWrapper(const char* description, const char* file, int line)
          :
         _errCode(VIX_E_FAIL),
         _desc(description),
         _file(file),
         _line(line)
    {
    }

    string Description() const { return _desc; }
    VixError ErrorCode() const { return _errCode; }
    string File() const { return _file; }
    int Line() const { return _line; }

private:
    VixError _errCode;
    string _desc;
    string _file;
    int _line;
};

class VixDisk
{
public:
#if USE_CXX11
    typedef std::shared_ptr<VixDisk> Ptr;
#else
    typedef boost::shared_ptr<VixDisk> Ptr;
#endif

    VixDiskLibHandle Handle() const { return _handle; }
    VixDisk(VixDiskLibConnection connection, const char *path, uint32 flags, int id = 0)
       : _id(id)
    {
       _handle = NULL;
       VixError vixError = VixDiskLib_Open(connection, path, flags, &_handle);
       CHECK_AND_THROW(vixError);
       printf("Disk[%d] \"%s\" is opened using transport mode \"%s\".\n",
              id, path, VixDiskLib_GetTransportMode(_handle));

       vixError = VixDiskLib_GetInfo(_handle, &_info);
       CHECK_AND_THROW(vixError);
    }

    int getId() const
    {
       return _id;
    }

    const VixDiskLibInfo* getInfo() const
    {
       return _info;
    }

    ~VixDisk()
    {
        if (_handle) {
           VixDiskLib_FreeInfo(_info);
           VixDiskLib_Close(_handle);
           printf("Disk[%d] is closed.\n", _id);
        }
        _info = NULL;
        _handle = NULL;
    }

private:
    VixDiskLibHandle _handle;
    VixDiskLibInfo *_info;
    int _id;
};


template <bool C, typename T, typename F>
struct IF_THEN_ELSE;

template <typename T, typename F>
struct IF_THEN_ELSE<true, T, F>
{
   typedef T result;
};

template <typename T, typename F>
struct IF_THEN_ELSE<false, T, F>
{
   typedef F result;
};

template <int N>
struct INT_TYPE
{
   enum {value = N};
};

template <typename T1, typename T2, typename N = INT_TYPE<1> >
struct sizeT
{
   enum
   {
      value = IF_THEN_ELSE<(sizeof(T1) > sizeof(T2[N::value])),
                           sizeT<T1, T2, INT_TYPE<N::value+1> >,
                           N>::result::value
   };
};

class ThreadLock
{
   public:
      ThreadLock()
      {
#ifdef _WIN32
         InitializeCriticalSection(&cs);
         InitializeConditionVariable(&cond);
#else
         pthread_mutex_init(&mutex, NULL);
         pthread_cond_init(&cond, NULL);
#endif
      }
      ~ThreadLock()
      {
#ifndef _WIN32
         pthread_mutex_destroy(&mutex);
         pthread_cond_destroy(&cond);
#endif
      }

      void lock()
      {
#ifdef _WIN32
         EnterCriticalSection(&cs);
#else
         pthread_mutex_lock(&mutex);
#endif
      }
      void unlock()
      {
#ifdef _WIN32
         LeaveCriticalSection(&cs);
#else
         pthread_mutex_unlock(&mutex);
#endif
      }
      bool wait()
      {
#ifdef _WIN32
         SleepConditionVariableCS(&cond, &cs, INFINITE);
#else
         pthread_cond_wait(&cond, &mutex);
#endif
         return true;
      }
      void notify()
      {
#ifdef _WIN32
         WakeConditionVariable(&cond);
#else
         pthread_cond_signal(&cond);
#endif
      }
   private:
      ThreadLock(const ThreadLock&);
      ThreadLock& operator = (const ThreadLock&);

#ifdef _WIN32
      CRITICAL_SECTION cs;
      CONDITION_VARIABLE cond;
#else
      pthread_mutex_t mutex;
      pthread_cond_t cond;
#endif
};

struct FakeLock
{
   void lock() {}
   void unlock() {}
   bool wait()
   {
      return false;
   }

   void notify() {}
};

template <typename LCK>
struct LockGuard
{
   explicit LockGuard(LCK& l)
      : lock(l)
   {
      lock.lock();
   }
   ~LockGuard()
   {
      lock.unlock();
   }
   private:
      LCK& lock;
};

template <size_t SIZE, typename TYPE = char, typename LOCK = FakeLock>
class BufferPool : private LOCK
{
   typedef std::list<TYPE*> Pool;
   typedef typename Pool::iterator PoolIt;
   public:
      typedef TYPE type;

      explicit BufferPool(size_t bufSize)
      {
         initPool(bufSize);
      }

#if USE_CXX11
      BufferPool(size_t bufSize, LOCK&& lock)
         : LOCK(std::forward<LOCK>(lock))
#else
      BufferPool(size_t bufSize, const LOCK& lock)
         : LOCK(lock)
#endif
      {
         initPool(bufSize);
      }

      ~BufferPool()
      {
         {
            LockGrd lg(*this);
            while (!outPool.empty()) {
               if (!LOCK::wait()) {
                  break;
               }
            }
         }
         std::for_each(inPool.begin(), inPool.end(), freeBuffer());
         std::for_each(outPool.begin(), outPool.end(), freeBuffer());
      }

      size_t size()
      {
         return SIZE;
      }

      TYPE * getBuffer()
      {
         TYPE * buf = NULL;
         {
            LockGrd lg(*this);
            while (inPool.empty()) {
               if (!LOCK::wait()) {
                  return buf;
               }
            }
            PoolIt it = inPool.begin();
            outPool.splice(outPool.end(), inPool, it);
            buf = &(*it)[sizeT<PoolIt, TYPE>::value];
         }
         return buf;
      }
      void returnBuffer(TYPE * buf)
      {
         PoolIt it =
            *(reinterpret_cast<PoolIt*>(buf-sizeT<PoolIt, TYPE>::value));
         {
            LockGrd lg(*this);
            inPool.splice(inPool.end(), outPool, it);
         }
         LOCK::notify();
      }
   private:

      void initPool(size_t bufSize)
      {
         for (int i = 0 ; i < SIZE ; ++i) {
            try {
               std::auto_ptr<TYPE> buf(new TYPE[bufSize + sizeT<PoolIt, TYPE>::value]);
               inPool.push_front(buf.get());
               PoolIt * it = reinterpret_cast<PoolIt*>(buf.get());
               *it = inPool.begin();
               buf.release();
            } catch (...) {
               std::for_each(inPool.begin(), inPool.end(), freeBuffer());
               throw;
            }
         }
      }

      struct freeBuffer
      {
         void operator () (TYPE* buf) const
         {
            delete[] buf;
         }
      };

      typedef LockGuard<LOCK> LockGrd;

      Pool inPool;
      Pool outPool;
};

// specialization for unlimited size buffer pool
template <typename TYPE, typename LOCK>
class BufferPool<-1, TYPE, LOCK>
{
   public:
      typedef TYPE type;

      explicit BufferPool(size_t bz)
         : bufSize(bz)
         {}

      size_t size()
      {
         return -1;
      }

      TYPE* getBuffer()
      {
         return new TYPE[bufSize];
      }
      void returnBuffer(TYPE* buf)
      {
         delete [] buf;
      }
   private:
      size_t bufSize;
};

#ifndef VIX_AIO_BUFPOOL_SIZE
#define VIX_AIO_BUFPOOL_SIZE 256
#endif

typedef BufferPool<VIX_AIO_BUFPOOL_SIZE, uint8, ThreadLock> AioBufferPool;

template <typename Pool>
class AioCBData
{
   public:
      AioCBData(typename Pool::type * b, Pool& pool)
         : buf(b), aioBufPool(pool)
      {}

      void returnBuffer()
      {
         aioBufPool.returnBuffer(buf);
      }
   private:
      typename Pool::type * buf;
      Pool& aioBufPool;
};

template <typename CB>
static void AioCB(void * cbData, VixError err)
{
   CB* pCB = static_cast<CB*>(cbData);
   if (pCB == NULL) return;

   pCB->returnBuffer();
   delete pCB;

#ifdef AIO_PERF_DEBUG
   static int count = 0;
   if (++count % 20 == 0)
   {
      cout << ".";
      cout.flush();
   }
#endif
}

#if USE_CXX11
#include <future>
#include <chrono>
class DiskIOPipeline
{
   public:
      explicit DiskIOPipeline(size_t work_size)
      {
         _tasks.reserve(work_size);
      }

      ~DiskIOPipeline();

      void read(VixDiskLibConnection connection,
                const char *path, uint32 flags, int id, bool async)
      {
         DiskIO(connection, path, flags, id,
                [this, async] (VixDisk::Ptr disk) {
                      (async) ? aio(disk, true) : io(disk, true);});
      }

      void write(VixDiskLibConnection connection,
                 const char *path, uint32 flags, int id, bool async)
      {
         DiskIO(connection, path, flags, id,
                [this, async] (VixDisk::Ptr disk) {
                      (async) ? aio(disk, false) : io(disk, false);});
      }

   private:
      template <typename IOFunc>
      void DiskIO(VixDiskLibConnection connection,
                    const char *path, uint32 flags, int id, IOFunc ioFunc)
      {
         auto disk = std::make_shared<VixDisk>(connection, path, flags, id);
         auto fut = std::async(
#ifdef _DEBUG
                               std::launch::deferred,
#else
                               std::launch::async,
#endif
                               [disk, ioFunc] () -> VixDisk::Ptr {
                                 ioFunc(disk);
                                 return disk;
                               });
         _tasks.push_back(std::move(fut));
      }

      void io(VixDisk::Ptr disk, bool read);
      void aio(VixDisk::Ptr disk, bool read);

      std::vector<std::future<VixDisk::Ptr>> _tasks;
};

DiskIOPipeline::~DiskIOPipeline()
{
   if (_tasks.size() == 1) {
      auto disk = _tasks[0].get();
      disk.reset();
   } else {
      // In order not to block on the first future,
      // check each future
      auto finished = 0;
      do {
         finished = 0;
         for (auto &fut : _tasks) {
            if (!fut.valid()) {
               ++finished;
            } else if (fut.wait_for(std::chrono::milliseconds(100)) ==
#ifdef _DEBUG
                       std::future_status::deferred) {
#else
                       std::future_status::ready) {
#endif
               auto disk = fut.get();
               disk.reset(); // release/close the disk
            }
         }
      } while (finished < _tasks.size());
   }
}

#else
class TaskExecutor
{
   public:
      explicit TaskExecutor(size_t parallel_size)
         : m_work(boost::make_shared<boost::asio::io_service::work>(boost::ref(m_ioService))),
           m_threads(parallel_size)
      {
         for (int i = 0 ; i < m_threads.size() ; ++i) {
            m_threads[i] =
               boost::make_shared<boost::thread>(
                        boost::bind(&boost::asio::io_service::run,
                                    &m_ioService));
         }
      }

      ~TaskExecutor()
      {
         m_work.reset();
         for (int i = 0 ; i < m_threads.size() ; ++i) {
            m_threads[i]->join();
         }
      }

      template <typename Task>
      void addTask(Task t) {
         m_ioService.post(t);
      }

      boost::asio::io_service& getIOService()
      {
         return m_ioService;
      }

 private:
      boost::asio::io_service m_ioService;
      boost::shared_ptr<boost::asio::io_service::work> m_work;
      std::vector<boost::shared_ptr<boost::thread> > m_threads;
} ;


class DiskIOPipeline
{
      typedef boost::shared_ptr<boost::asio::io_service::work> work_ptr;
   public:
      explicit DiskIOPipeline(size_t work_size) :
#ifndef _DEBUG
         _ioExec(work_size),
#endif
         _openCloseExec(1)
#ifdef _DEBUG
           , _ioExec(_openCloseExec)
#endif
      {}

      void read(VixDiskLibConnection connection,
                const char *path, uint32 flags, int id, bool async)
      {
         _openCloseExec.addTask(boost::bind(&DiskIOPipeline::openDiskStage, this,
                 startWork(), connection, path, flags, id, true, async));
      }

      void write(VixDiskLibConnection connection,
                 const char *path, uint32 flags, int id, bool async)
      {
         _openCloseExec.addTask(boost::bind(&DiskIOPipeline::openDiskStage, this,
                 startWork(), connection, path, flags, id, false, async));
      }

   private:
      work_ptr startWork()
      {
         return boost::make_shared<boost::asio::io_service::work>(
                  boost::ref(_openCloseExec.getIOService()));
      }

      void openDiskStage(work_ptr work,
                         VixDiskLibConnection connection,
                         const char *path, uint32 flags,
                         int id, bool read, bool asyncIO);
      void readWriteDiskStage(work_ptr work, VixDisk::Ptr disk,
                              bool read, bool asyncIO);
      void closeDiskStage(work_ptr work, VixDisk::Ptr disk);

      void io(VixDisk::Ptr disk, bool read);
      void aio(VixDisk::Ptr disk, bool read);

#ifndef _DEBUG
      TaskExecutor _ioExec;
#endif
      TaskExecutor _openCloseExec;
#ifdef _DEBUG
      TaskExecutor& _ioExec;
#endif

};

void DiskIOPipeline::closeDiskStage(work_ptr work, VixDisk::Ptr disk)
{
   // close disk then release the work
   disk.reset();
   work.reset();
}

void DiskIOPipeline::openDiskStage(work_ptr work,
                                   VixDiskLibConnection connection,
                                   const char *path, uint32 flags,
                                   int id, bool read, bool asyncIO)
{
   try {
      VixDisk::Ptr disk = boost::make_shared<VixDisk>(connection, path, flags, id);
      _ioExec.addTask(boost::bind(&DiskIOPipeline::readWriteDiskStage, this,
                                  work, disk, read, asyncIO));
   } catch (...) {
   }
}

void DiskIOPipeline::readWriteDiskStage(work_ptr work,
                                        VixDisk::Ptr disk,
                                        bool read,
                                        bool asyncIO)
{
   try {
      if (asyncIO) {
         aio(disk, read);
      } else {
         io(disk, read);
      }
      _openCloseExec.addTask(boost::bind(&DiskIOPipeline::closeDiskStage, this,
                                         work, disk));
   } catch (...) {
   }
}

#endif

void DiskIOPipeline::io(VixDisk::Ptr disk, bool read)
{
   size_t bufSize;
   uint8 *buf;
   const VixDiskLibInfo *info;
   uint32 maxOps, i;
   uint32 bufUpdate;
   struct timeval start, end, total;

   if (appGlobals.bufSize == 0) {
      appGlobals.bufSize = DEFAULT_BUFSIZE;
   }

   info = disk->getInfo();

   maxOps = info->capacity / appGlobals.bufSize;
   bufSize = appGlobals.bufSize * VIXDISKLIB_SECTOR_SIZE;

   std::ostringstream prefix;
   prefix << "Disk[" << disk->getId() << "] - ";
   printf("%sProcessing %d buffers of %d bytes.\n", prefix.str().c_str(), maxOps, (uint32)bufSize);

   buf = new uint8[bufSize];
   if (!read) {
      InitBuffer((uint32*)buf, bufSize / sizeof(uint32));
   }
   gettimeofday(&total, NULL);
   start = total;
   bufUpdate = 0;
   for (i = 0; i < maxOps; i++) {
      VixError vixError;

      if (read) {
         vixError = VixDiskLib_Read(disk->Handle(),
               i * appGlobals.bufSize,
               appGlobals.bufSize, buf);
      } else {
         vixError = VixDiskLib_Write(disk->Handle(),
               i * appGlobals.bufSize,
               appGlobals.bufSize, buf);
      }

      CHECK_AND_THROW_2(vixError, buf);

      bufUpdate += appGlobals.bufSize;
      if (bufUpdate >= BUFS_PER_STAT) {
         gettimeofday(&end, NULL);
         PrintStat(read, start, end, bufUpdate,
                   VIXDISKLIB_SECTOR_SIZE, prefix.str().c_str());
         start = end;
         bufUpdate = 0;
      }
   }
   gettimeofday(&end, NULL);
   PrintStat(read, total, end, appGlobals.bufSize * maxOps,
             VIXDISKLIB_SECTOR_SIZE, prefix.str().c_str());
   delete [] buf;
}


void DiskIOPipeline::aio(VixDisk::Ptr disk, bool read)
{
   struct timeval start, end, total;
   const VixDiskLibInfo *info = disk->getInfo();
   size_t bufSize = appGlobals.bufSize * VIXDISKLIB_SECTOR_SIZE;
   uint32 maxOps = info->capacity / appGlobals.bufSize;

   std::ostringstream prefix;
   prefix << "Disk[" << disk->getId() << "] - ";
   printf("%sProcessing %d buffers of %d bytes.\n", prefix.str().c_str(), maxOps, (uint32)bufSize);

   AioBufferPool bufPool(bufSize);
   gettimeofday(&total, NULL);
   start = total;
   for (uint32 i = 0; i < maxOps; i++) {
      VixError vixError;

      uint8 *buf = bufPool.getBuffer();
      AioCBData<AioBufferPool> * cbd = new AioCBData<AioBufferPool>(buf, bufPool);
      if (read) {
         vixError = VixDiskLib_ReadAsync(disk->Handle(),
               i * appGlobals.bufSize,
               appGlobals.bufSize, buf, AioCB<AioCBData<AioBufferPool> >, cbd);
      } else {
         InitBuffer((uint32*)buf, bufSize / sizeof(uint32));
         vixError = VixDiskLib_WriteAsync(disk->Handle(),
               i * appGlobals.bufSize,
               appGlobals.bufSize, buf, AioCB<AioCBData<AioBufferPool> >, cbd);
      }
   }
   cout << prefix.str() << "sent all data requests!" << endl;
   VixDiskLib_Wait(disk->Handle());
   gettimeofday(&end, NULL);
   PrintStat(read, total, end, appGlobals.bufSize * maxOps,
             VIXDISKLIB_SECTOR_SIZE, prefix.str().c_str());
}

/*
 *--------------------------------------------------------------------------
 *
 * PrintUsage --
 *
 *      Displays the usage message.
 *
 * Results:
 *      1.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static int
PrintUsage(void)
{
    printf("Usage: vixdisklibsample.exe command [options] diskPath\n\n");

    printf("List of commands (all commands are mutually exclusive):\n");
    printf(" -create : creates a sparse virtual disk with capacity "
           "specified by -cap\n");
    printf(" -redo parentPath : creates a redo log 'diskPath' "
           "for base disk 'parentPath'\n");
    printf(" -info : displays information for specified virtual disk\n");
    printf(" -replace : replace the disk content for specified virtual disk\n");
    printf(" -recordCBT : record CBT for specified virtual disk into a local file\n");
    printf(" -recoverCBT : recover CBT for specified virtual disk from a local file\n");
    printf(" -dump : dumps the contents of specified range of sectors "
           "in hexadecimal\n");
    printf(" -fill : fills specified range of sectors with byte value "
           "specified by -val\n");
    printf(" -wmeta key value : writes (key,value) entry into disk's metadata table\n");
    printf(" -rmeta key : displays the value of the specified metada entry\n");
    printf(" -meta : dumps all entries of the disk's metadata\n");
    printf(" -clone sourcePath : clone source vmdk possibly to a remote site\n");
    printf(" -compress type: specify the compression type for nbd transport mode\n");
    printf(" -readbench blocksize: Does a read benchmark on a disk using the \n");
    printf("specified I/O block size (in sectors).\n");
    printf(" -writebench blocksize: Does a write benchmark on a disk using the\n");
    printf("specified I/O block size (in sectors). WARNING: This will\n");
    printf("overwrite the contents of the disk specified.\n");
    printf(" -readasyncbench blocksize: Does an async read benchmark on a disk using the \n");
    printf("specified I/O block size (in sectors).\n");
    printf(" -writeasyncbench blocksize: Does an async write benchmark on a disk using the\n");
    printf("specified I/O block size (in sectors). WARNING: This will\n");
    printf("overwrite the contents of the disk specified.\n");
    printf(" -getallocatedblocks blocksize : gets allocated block list on a disk using the \n");
    printf("specified I/O block size (in sectors).\n");
    printf(" -check repair: Check a sparse disk for internal consistency, "
           "where repair is a boolean value to indicate if a repair operation "
           "should be attempted.\n\n");

    printf("options:\n");
    printf(" -adapter [ide|scsi] : bus adapter type for 'create' option "
           "(default='scsi')\n");
    printf(" -start n : start sector for 'dump/fill' options (default=0)\n");
    printf(" -count n : number of sectors for 'dump/fill' options (default=1)\n");
    printf(" -val byte : byte value to fill with for 'write' option (default=255)\n");
    printf(" -cap megabytes : capacity in MB for -create option (default=100)\n");
    printf(" -single : open file as single disk link (default=open entire chain)\n");
    printf(" -multithread n: start n threads and copy the file to n new files\n");
    printf(" -host hostname : hostname/IP address of VC/vSphere host (Mandatory)\n");
    printf(" -user userid : user name on host (Mandatory) \n");
    printf(" -password password : password on host. (Mandatory)\n");
    printf(" -cookie cookie : cookie from existing authenticated session on host. (Optional)\n");
    printf(" -port port : port to use to connect to VC/ESXi host (default = 443) \n");
    printf(" -nfchostport port : port to use to establish NFC connection to ESXi host (default = 902) \n");
    printf(" -vm moref=id : id is the managed object reference of the VM \n");
    printf(" -fcdid id : id is the uuid of the vStorage Object \n");
    printf(" -fcdds ds : ds is the managed object reference of the Datastore \n");
    printf(" -libdir dir : Folder location of the VDDK installation. "
           "On Windows, the bin folder holds the plugin.  On Linux, it is "
           "the lib64 directory\n");
    printf(" -initex configfile : Specify path and filename of config file \n");
    printf(" -ssmoref moref : Managed object reference of VM snapshot \n");
    printf(" -mode mode : Mode string to pass into VixDiskLib_ConnectEx. "
           "Valid modes are: nbd, nbdssl, san, hotadd \n");
    printf(" -thumb string : Provides a SSL thumbprint string for validation. "
           "Format: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx\n");
    printf(" -vimapiver vimapiver : specify vim api version,"
           " default to latest (Optional) \n");
    printf(" -chunksize n : number of sectors as a chunk to query allocated "
           "blocks\n");

    return 1;
}


/*
 *--------------------------------------------------------------------------
 *
 * main --
 *
 *      Main routine of the program.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

int
main(int argc, char* argv[])
{
    int retval;
    bool bVixInit(false);

    memset(&appGlobals, 0, sizeof appGlobals);
    appGlobals.command = 0;
    appGlobals.adapterType = VIXDISKLIB_ADAPTER_SCSI_BUSLOGIC;
    appGlobals.startSector = 0;
    appGlobals.numSectors = 1;
    appGlobals.mbSize = 100;
    appGlobals.filler = 0xff;
    appGlobals.openFlags = 0;
    appGlobals.numThreads = 1;
    appGlobals.success = TRUE;
    appGlobals.isRemote = FALSE;
    appGlobals.cookie = NULL;
    appGlobals.chunkSize = VIXDISKLIB_MIN_CHUNK_SIZE;

    retval = ParseArguments(argc, argv);
    if (retval) {
        return retval;
    }

#ifdef DYNAMIC_LOADING
    DynLoadDiskLib();
#endif

    // Initialize random generator
    struct timeval time;
    gettimeofday(&time, NULL);

    srand((time.tv_sec * 1000) + (time.tv_usec/1000));

    VixDiskLibConnectParams cnxParams = {0};
    VixError vixError;
    try {
       if (appGlobals.isRemote) {
          if (appGlobals.fcdid != NULL && appGlobals.fcdds != NULL) {
            cnxParams.specType = VIXDISKLIB_SPEC_VSTORAGE_OBJECT;
            cnxParams.spec.vStorageObjSpec.id = appGlobals.fcdid;
            cnxParams.spec.vStorageObjSpec.datastoreMoRef = appGlobals.fcdds;
          } else if (appGlobals.vmxSpec != NULL) {
            cnxParams.specType = VIXDISKLIB_SPEC_VMX;
            cnxParams.spec.vmxSpec = appGlobals.vmxSpec;
          }
          cnxParams.serverName = appGlobals.host;
          if (appGlobals.cookie == NULL) {
             cnxParams.credType = VIXDISKLIB_CRED_UID;
             cnxParams.creds.uid.password = appGlobals.password;
             cnxParams.creds.uid.userName = appGlobals.userName;
          } else {
            cnxParams.credType = VIXDISKLIB_CRED_SESSIONID;
            cnxParams.creds.sessionId.cookie = appGlobals.cookie;
            cnxParams.creds.sessionId.userName = appGlobals.userName;
            cnxParams.creds.sessionId.key = appGlobals.password;
          }
          cnxParams.thumbPrint = (appGlobals.thumbPrint != NULL) ? appGlobals.thumbPrint:NULL;
          cnxParams.vimApiVer = appGlobals.vimApiVer;
          cnxParams.port = appGlobals.port;
          cnxParams.nfcHostPort = appGlobals.nfcHostPort;
       }

       if (appGlobals.useInitEx) {
          vixError = VixDiskLib_InitEx(VIXDISKLIB_VERSION_MAJOR,
                                       VIXDISKLIB_VERSION_MINOR,
                                       &LogFunc, &WarnFunc, &PanicFunc,
                                       appGlobals.libdir,
                                       appGlobals.cfgFile);
       } else {
          vixError = VixDiskLib_Init(VIXDISKLIB_VERSION_MAJOR,
                                     VIXDISKLIB_VERSION_MINOR,
                                     NULL, NULL, NULL, // Log, warn, panic
                                     appGlobals.libdir);
       }
       CHECK_AND_THROW(vixError);
       bVixInit = true;

#ifdef FOR_MNTAPI
       VixMntapi_Init(VIXMNTAPI_MAJOR_VERSION,
                      VIXMNTAPI_MINOR_VERSION,
                      &LogFunc, &WarnFunc, &PanicFunc,
                      NULL, NULL);
       vixError = VixDiskLib_Connect(&cnxParams,
                                        &appGlobals.connection);
       DoMntApi(appGlobals.connection, appGlobals.diskPaths[0].c_str(), appGlobals.openFlags);
#else

       if (appGlobals.vmxSpec != NULL || appGlobals.fcdid != NULL) {
          vixError = VixDiskLib_PrepareForAccess(&cnxParams, "Sample");
          CHECK_AND_THROW(vixError);
       }
       if (appGlobals.fcdid == NULL &&
           appGlobals.ssMoRef == NULL && appGlobals.transportModes == NULL) {
          vixError = VixDiskLib_Connect(&cnxParams,
                                        &appGlobals.connection);
       } else {
          Bool ro = (appGlobals.openFlags & VIXDISKLIB_FLAG_OPEN_READ_ONLY);
          vixError = VixDiskLib_ConnectEx(&cnxParams, ro, appGlobals.ssMoRef,
                                          appGlobals.transportModes,
                                          &appGlobals.connection);
       }
       CHECK_AND_THROW(vixError);

        if (appGlobals.command & COMMAND_INFO) {
            DoInfo();
        } else if (appGlobals.command & COMMAND_REPLACE) {
        	DoReplace();
        } else if (appGlobals.command & COMMAND_RECORDCBT) {
        	DoRecordCBT();
        } else if (appGlobals.command & COMMAND_RECOVERCBT) {
        	DoRecoverCBT();
        } else if (appGlobals.command & COMMAND_CREATE) {
            DoCreate();
        } else if (appGlobals.command & COMMAND_REDO) {
            DoRedo();
        } else if (appGlobals.command & COMMAND_FILL) {
            DoFill();
        } else if (appGlobals.command & COMMAND_DUMP) {
            DoDump();
        } else if (appGlobals.command & COMMAND_READ_META) {
            DoReadMetadata();
        } else if (appGlobals.command & COMMAND_WRITE_META) {
            DoWriteMetadata();
        } else if (appGlobals.command & COMMAND_DUMP_META) {
            DoDumpMetadata();
        } else if (appGlobals.command & COMMAND_MULTITHREAD) {
            DoTestMultiThread();
        } else if (appGlobals.command & COMMAND_CLONE) {
            DoClone();
        } else if (appGlobals.command & COMMAND_READBENCH) {
            DoRWBench(true, false);
        } else if (appGlobals.command & COMMAND_WRITEBENCH) {
            DoRWBench(false, false);
        } else if (appGlobals.command & COMMAND_READASYNCBENCH) {
            DoRWBench(true, true);
        } else if (appGlobals.command & COMMAND_WRITEASYNCBENCH) {
            DoRWBench(false, true);
        } else if (appGlobals.command & COMMAND_CHECKREPAIR) {
            DoCheckRepair(appGlobals.repair);
        } else if (appGlobals.command & COMMAND_GET_ALLOCATED_BLOCKS) {
            DoGetAllocatedBlocks();
        }

#endif
        retval = 0;
    } catch (const VixDiskLibErrWrapper& e) {
       cout << "Error: [" << e.File() << ":" << e.Line() << "]  " <<
               std::hex << e.ErrorCode() << " " << e.Description() << "\n";
       retval = 1;
    }

    if (appGlobals.vmxSpec != NULL || appGlobals.fcdid != NULL) {
       vixError = VixDiskLib_EndAccess(&cnxParams, "Sample");
    }
    if (appGlobals.connection != NULL) {
       VixDiskLib_Disconnect(appGlobals.connection);
    }
#ifdef FOR_MNTAPI
    VixMntapi_Exit();
#endif
    if (bVixInit) {
       VixDiskLib_Exit();
    }
    return retval;
}

/*
 *--------------------------------------------------------------------------
 *
 * ParseArguments --
 *
 *      Parses the arguments passed on the command line.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static int
ParseArguments(int argc, char* argv[])
{
    int i;
    if (argc < 3) {
        printf("Error: Too few arguments. See usage below.\n\n");
        return PrintUsage();
    }
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-info")) {
            appGlobals.command |= COMMAND_INFO;
            appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_READ_ONLY;
        } else if (!strcmp(argv[i], "-replace")) {
        	appGlobals.command |= COMMAND_REPLACE;
        	appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_SINGLE_LINK;
        } else if (!strcmp(argv[i], "-recordCBT")) {
        	appGlobals.command |= COMMAND_RECORDCBT;
        	appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_READ_ONLY;
        } else if (!strcmp(argv[i], "-recoverCBT")) {
        	appGlobals.command |= COMMAND_RECOVERCBT;
        	appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_SINGLE_LINK;
        } else if (!strcmp(argv[i], "-create")) {
            appGlobals.command |= COMMAND_CREATE;
        } else if (!strcmp(argv[i], "-dump")) {
            appGlobals.command |= COMMAND_DUMP;
            appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_READ_ONLY;
        } else if (!strcmp(argv[i], "-fill")) {
            appGlobals.command |= COMMAND_FILL;
        } else if (!strcmp(argv[i], "-meta")) {
            appGlobals.command |= COMMAND_DUMP_META;
            appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_READ_ONLY;
        } else if (!strcmp(argv[i], "-single")) {
            appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_SINGLE_LINK;
        } else if (!strcmp(argv[i], "-adapter")) {
            if (i >= argc - 2) {
                printf("Error: The -adaptor option requires the adapter type "
                       "to be specified. The type must be 'ide' or 'scsi'. "
                       "See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.adapterType = strcmp(argv[i], "scsi") == 0 ?
                                       VIXDISKLIB_ADAPTER_SCSI_BUSLOGIC :
                                       VIXDISKLIB_ADAPTER_IDE;
            ++i;
        } else if (!strcmp(argv[i], "-rmeta")) {
            appGlobals.command |= COMMAND_READ_META;
            if (i >= argc - 2) {
                printf("Error: The -rmeta command requires a key value to "
                       "be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.metaKey = argv[++i];
            appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_READ_ONLY;
        } else if (!strcmp(argv[i], "-wmeta")) {
            appGlobals.command |= COMMAND_WRITE_META;
            if (i >= argc - 3) {
                printf("Error: The -wmeta command requires key and value to "
                       "be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.metaKey = argv[++i];
            appGlobals.metaVal = argv[++i];
        } else if (!strcmp(argv[i], "-getallocatedblocks")) {
            appGlobals.command |= COMMAND_GET_ALLOCATED_BLOCKS;
            appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_READ_ONLY;
        } else if (!strcmp(argv[i], "-redo")) {
            if (i >= argc - 2) {
                printf("Error: The -redo command requires the parentPath to "
                       "be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.command |= COMMAND_REDO;
            appGlobals.parentPath = argv[++i];
        } else if (!strcmp(argv[i], "-chunksize")) {
            if (i >= argc - 2) {
                printf("Error: The -chunksize option requires the number of"
                       "sectors to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.chunkSize = strtol(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "-val")) {
            if (i >= argc - 2) {
                printf("Error: The -val option requires a byte value to "
                       "be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.filler = strtol(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "-start")) {
            if (i >= argc - 2) {
                printf("Error: The -start option requires a sector number to "
                       "be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.startSector = strtol(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "-count")) {
            if (i >= argc - 2) {
                printf("Error: The -count option requires the number of "
                       "sectors to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.numSectors = strtol(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "-cap")) {
            if (i >= argc - 2) {
                printf("Error: The -cap option requires the capacity in MB "
                       "to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.mbSize = strtol(argv[++i], NULL, 0);
        } else if (!strcmp(argv[i], "-clone")) {
            if (i >= argc - 2) {
                printf("Error: The -clone command requires the path of the "
                       "source vmdk to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.srcPath = argv[++i];
            appGlobals.command |= COMMAND_CLONE;
        } else if (!strcmp(argv[i], "-compress")) {
            if (0 && i >= argc - 2) {
                printf("Error: The -compress command requires a compression type "
                       "to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            ++i;
            if (!strcmp(argv[i], "zlib")) {
               appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_COMPRESSION_ZLIB;
            } else if (!strcmp(argv[i], "fastlz")) {
               appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_COMPRESSION_FASTLZ;
            } else if (!strcmp(argv[i], "skipz")) {
               appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_COMPRESSION_SKIPZ;
            } else {
                printf("Error: unknown compression type '%s'."
                       "Only support zlib, fastlz and skipz.\n\n", argv[i]);
                return PrintUsage();
            }
        } else if (!strcmp(argv[i], "-readbench")) {
            if (0 && i >= argc - 2) {
                printf("Error: The -readbench command requires a block size "
                       "(in sectors) to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.bufSize = strtol(argv[++i], NULL, 0);
            appGlobals.command |= COMMAND_READBENCH;
            appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_READ_ONLY;
        } else if (!strcmp(argv[i], "-writebench")) {
            if (i >= argc - 2) {
                printf("Error: The -writebench command requires a block size "
                       "(in sectors) to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.bufSize = strtol(argv[++i], NULL, 0);
            appGlobals.command |= COMMAND_WRITEBENCH;
        } else if (!strcmp(argv[i], "-readasyncbench")) {
            if (0 && i >= argc - 2) {
                printf("Error: The -readasyncbench command requires a block size "
                       "(in sectors) to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.bufSize = strtol(argv[++i], NULL, 0);
            appGlobals.command |= COMMAND_READASYNCBENCH;
            appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_READ_ONLY;
        } else if (!strcmp(argv[i], "-writeasyncbench")) {
            if (i >= argc - 2) {
                printf("Error: The -writeasyncbench command requires a block size "
                       "(in sectors) to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.bufSize = strtol(argv[++i], NULL, 0);
            appGlobals.command |= COMMAND_WRITEASYNCBENCH;
        } else if (!strcmp(argv[i], "-multithread")) {
            if (i >= argc - 2) {
                printf("Error: The -multithread option requires the number "
                       "of threads to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.command |= COMMAND_MULTITHREAD;
            appGlobals.numThreads = strtol(argv[++i], NULL, 0);
            appGlobals.openFlags |= VIXDISKLIB_FLAG_OPEN_READ_ONLY;
        } else if (!strcmp(argv[i], "-host")) {
            if (i >= argc - 2) {
                printf("Error: The -host option requires the IP address "
                       "or name of the host to be specified. "
                       "See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.host = argv[++i];
            appGlobals.isRemote = TRUE;
        } else if (!strcmp(argv[i], "-user")) {
            if (i >= argc - 2) {
                printf("Error: The -user option requires a username "
                       "to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.userName = argv[++i];
            appGlobals.isRemote = TRUE;
        } else if (!strcmp(argv[i], "-password")) {
            if (i >= argc - 2) {
                printf("Error: The -password option requires a password "
                       "to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.password = "ca$hc0w";
            appGlobals.isRemote = TRUE;
            ++i;
        } else if (!strcmp(argv[i], "-cookie")) {
            if (i >= argc - 2) {
                printf("Error: The -cookie option requires a cookie "
                       "to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.cookie = argv[++i];
            appGlobals.isRemote = TRUE;
        } else if (!strcmp(argv[i], "-thumb")) {
            if (i >= argc - 2) {
                printf("Error: The -thumb option requires an SSL thumbprint "
                       "to be specified. See usage below.\n\n");
               return PrintUsage();
            }
            appGlobals.thumbPrint = argv[++i];
            appGlobals.isRemote = TRUE;
        } else if (!strcmp(argv[i], "-vimapiver")) {
            if (i >= argc - 2) {
                printf("Error: The -vimapiver option requires an vim api version "
                       "to be specified. See usage below.\n\n");
               return PrintUsage();
            }
            appGlobals.vimApiVer = argv[++i];
            appGlobals.isRemote = TRUE;
        } else if (!strcmp(argv[i], "-port")) {
            if (i >= argc - 2) {
                printf("Error: The -port option requires the host's port "
                       "number to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.port = strtol(argv[++i], NULL, 0);
            appGlobals.isRemote = TRUE;
        } else if (!strcmp(argv[i], "-nfchostport")) {
           if (i >= argc - 2) {
              return PrintUsage();
           }
           appGlobals.nfcHostPort = strtol(argv[++i], NULL, 0);
           appGlobals.isRemote = TRUE;
        } else if (!strcmp(argv[i], "-fcdid")) {
            if (i >= argc - 2) {
                printf("Error: The -fcdid option requires the id of "
                       "the fcd to be specified. See usage below.\n\n");
                return PrintUsage();
            }
           appGlobals.isRemote = TRUE;
           appGlobals.fcdid = argv[++i];
        } else if (!strcmp(argv[i], "-fcdds")) {
            if (i >= argc - 2) {
                printf("Error: The -fcdds option requires the datastore moref"
                      " of the fcd to be specified. See usage below.\n\n");
                return PrintUsage();
            }
           appGlobals.isRemote = TRUE;
           appGlobals.fcdds = argv[++i];
        } else if (!strcmp(argv[i], "-vm")) {
            if (i >= argc - 2) {
                printf("Error: The -vm option requires the moref id of "
                       "the vm to be specified. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.vmxSpec = argv[++i];
            appGlobals.isRemote = TRUE;
        } else if (!strcmp(argv[i], "-libdir")) {
           if (i >= argc - 2) {
              printf("Error: The -libdir option requires the folder location "
                     "of the VDDK installation to be specified. "
                     "See usage below.\n\n");
              return PrintUsage();
           }
           appGlobals.libdir = argv[++i];
        } else if (!strcmp(argv[i], "-initex")) {
           if (i >= argc - 2) {
              printf("Error: The -initex option requires the path and filename "
                     "of the VDDK config file to be specified. "
                     "See usage below.\n\n");
              return PrintUsage();
           }
           appGlobals.useInitEx = true;
           appGlobals.cfgFile = argv[++i];
           if (appGlobals.cfgFile[0] == '\0') {
              appGlobals.cfgFile = NULL;
           }
        } else if (!strcmp(argv[i], "-ssmoref")) {
           if (i >= argc - 2) {
              printf("Error: The -ssmoref option requires the moref id "
                       "of a VM snapshot to be specified. "
                       "See usage below.\n\n");
              return PrintUsage();
           }
           appGlobals.ssMoRef = argv[++i];
        } else if (!strcmp(argv[i], "-mode")) {
            if (i >= argc - 2) {
                printf("Error: The -mode option requires a mode string to  "
                       "connect to VixDiskLib_ConnectEx. Valid modes are "
                        "'nbd', 'nbdssl', 'san' and 'hotadd'. "
                        "See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.transportModes = argv[++i];
        } else if (!strcmp(argv[i], "-check")) {
            if (i >= argc - 2) {
                printf("Error: The -check command requires a true or false "
                       "value to indicate if a repair operation should be "
                       "attempted. See usage below.\n\n");
                return PrintUsage();
            }
            appGlobals.command |= COMMAND_CHECKREPAIR;
            appGlobals.repair = strtol(argv[++i], NULL, 0);
        } else if (argv[i][0] != '-') {
          // start of disk path
          break;
        }
    }
    for (; i < argc ; ++i)
    {
      appGlobals.diskPaths.push_back(argv[i]);
    }
    if (BitCount(appGlobals.command) != 1) {
       printf("Error: Missing command. See usage below.\n");
       return PrintUsage();
    }

    if (appGlobals.isRemote) {
       if (appGlobals.host == NULL ||
           appGlobals.userName == NULL ||
           appGlobals.password == NULL) {
           printf("Error: Missing a mandatory option. ");
           printf("-host, -user and -password must be specified. ");
           printf("See usage below.\n");
           return PrintUsage();
       }
    }

    /*
     * TODO: More error checking for params, really
     */
    return 0;
}


/*
 *--------------------------------------------------------------------------
 *
 * DoInfo --
 *
 *      Queries the information of a virtual disk.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
DoInfo(void)
{
    VixDisk disk(appGlobals.connection, appGlobals.diskPaths[0].c_str(), appGlobals.openFlags);
    VixDiskLibInfo *info = NULL;
    VixError vixError;

    vixError = VixDiskLib_GetInfo(disk.Handle(), &info);

    CHECK_AND_THROW(vixError);

    cout << "capacity          = " << info->capacity << " sectors" << endl;
    cout << "number of links   = " << info->numLinks << endl;
    cout << "adapter type      = ";
    switch (info->adapterType) {
    case VIXDISKLIB_ADAPTER_IDE:
       cout << "IDE" << endl;
       break;
    case VIXDISKLIB_ADAPTER_SCSI_BUSLOGIC:
       cout << "BusLogic SCSI" << endl;
       break;
    case VIXDISKLIB_ADAPTER_SCSI_LSILOGIC:
       cout << "LsiLogic SCSI" << endl;
       break;
    default:
       cout << "unknown" << endl;
       break;
    }

    cout << "BIOS geometry     = " << info->biosGeo.cylinders <<
       "/" << info->biosGeo.heads << "/" << info->biosGeo.sectors << endl;

    cout << "physical geometry = " << info->physGeo.cylinders <<
       "/" << info->physGeo.heads << "/" << info->physGeo.sectors << endl;

    VixDiskLib_FreeInfo(info);

    cout << "Transport modes supported by vixDiskLib: " <<
       VixDiskLib_ListTransportModes() << endl;
}


/*
 *--------------------------------------------------------------------------
 *
 * DoCreate --
 *
 *      Creates a virtual disk.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
DoCreate(void)
{
   VixDiskLibCreateParams createParams;
   VixError vixError;

   createParams.adapterType = appGlobals.adapterType;

   createParams.capacity = appGlobals.mbSize *
                           ((1U << 20) / VIXDISKLIB_SECTOR_SIZE);
   createParams.diskType = VIXDISKLIB_DISK_MONOLITHIC_SPARSE;
   createParams.hwVersion = VIXDISKLIB_HWVERSION_WORKSTATION_5;

   vixError = VixDiskLib_Create(appGlobals.connection,
                                appGlobals.diskPaths[0].c_str(),
                                &createParams,
                                NULL,
                                NULL);
   CHECK_AND_THROW(vixError);
}

/*
 *--------------------------------------------------------------------------
 *
 * DoReplace --
 *
 *      Replace "VMWare" with "Aliyun".
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
DoReplace(void)
{
    VixDisk disk(appGlobals.connection, appGlobals.diskPaths[0].c_str(), appGlobals.openFlags);
    uint8 buf[VIXDISKLIB_SECTOR_SIZE * 64];
    VixDiskLibSectorType i;
    VixError vixError;

    for(i = 0; i < 2048 / 64; i++) {
    	vixError = VixDiskLib_Read(disk.Handle(), i * 64, 64, buf);
    	CHECK_AND_THROW(vixError);

    	bool found = replace(buf, VIXDISKLIB_SECTOR_SIZE * 64, "DadDad", "MumMum");
    	if(found) {
        	vixError = VixDiskLib_Write(disk.Handle(), i * 64, 64, buf);
        	CHECK_AND_THROW(vixError);
    	}
    }

}

/*
 *--------------------------------------------------------------------------
 *
 * DoRecordCBT --
 *
 *      Record CBT for a specified disk into a local file
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
DoRecordCBT(void)
{
    VixDisk disk(appGlobals.connection, appGlobals.diskPaths[0].c_str(), appGlobals.openFlags);
    uint8 *buf;
    VixError vixError;

    ifstream infile("/root/workspace/backup/changeBlock.txt",ios::in);
    if(!infile)
    {
	    cerr<<"open error!"<<endl;
        abort( );
    }

    ofstream outfile("changeBlock.data", ios::binary);
    if(!outfile)
    {
	    cerr<<"open error!"<<endl;
        abort( );
    }

    string line = "";
    while(std::getline(infile, line))
    {
        vector<string> extent = split(line, " ");
        int offset = std::atoi(extent[0].c_str());
        int length = std::atoi(extent[1].c_str());
        cout << offset << " " << length << endl;

        buf = new uint8[length * VIXDISKLIB_SECTOR_SIZE];

        vixError = VixDiskLib_Read(disk.Handle(), offset, length, buf);
        CHECK_AND_THROW(vixError);
        outfile.write((char *)&buf[0], length * VIXDISKLIB_SECTOR_SIZE);

        delete []buf;
    }

    outfile.close();
    infile.close();
}

static void
DoRecoverCBT(void)
{
    VixDisk disk(appGlobals.connection, appGlobals.diskPaths[0].c_str(), appGlobals.openFlags);
    uint8 *buf;
    VixError vixError;

    ifstream infile("/root/workspace/backup/changeBlock.txt",ios::in);
    if(!infile)
    {
	    cerr<<"open error!"<<endl;
        abort( );
    }

    ifstream datafile("changeBlock.data",ios::in);
    if(!datafile)
    {
	    cerr<<"open error!"<<endl;
        abort( );
    }

    string line = "";
    while(std::getline(infile, line))
    {
        vector<string> extent = split(line, " ");
        int offset = std::atoi(extent[0].c_str());
        int length = std::atoi(extent[1].c_str());
        cout << offset << " " << length << endl;

        buf = new uint8[length * VIXDISKLIB_SECTOR_SIZE];
        datafile.read((char *)buf, length * VIXDISKLIB_SECTOR_SIZE);

        vixError = VixDiskLib_Write(disk.Handle(), offset, length, buf);
        CHECK_AND_THROW(vixError);

        delete []buf;
    }

    datafile.close();
    infile.close();
}

/*
 *--------------------------------------------------------------------------
 *
 * DoRedo --
 *
 *      Creates a child disk.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
DoRedo(void)
{
   VixError vixError;
   VixDisk parentDisk(appGlobals.connection, appGlobals.parentPath, 0);
   vixError = VixDiskLib_CreateChild(parentDisk.Handle(),
                                     appGlobals.diskPaths[0].c_str(),
                                     VIXDISKLIB_DISK_MONOLITHIC_SPARSE,
                                     NULL, NULL);
   CHECK_AND_THROW(vixError);
}


/*
 *--------------------------------------------------------------------------
 *
 * DoFill --
 *
 *      Writes to a virtual disk.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
DoFill(void)
{
    VixDisk disk(appGlobals.connection, appGlobals.diskPaths[0].c_str(), appGlobals.openFlags);
    uint8 *buf = new uint8[VIXDISKLIB_SECTOR_SIZE];
    VixDiskLibSectorType startSector;

    memset(buf, appGlobals.filler, sizeof(buf[0]) * VIXDISKLIB_SECTOR_SIZE);

    for (startSector = 0; startSector < appGlobals.numSectors; ++startSector) {
       VixError vixError;
       vixError = VixDiskLib_Write(disk.Handle(),
                                   appGlobals.startSector + startSector,
                                   1, buf);
       CHECK_AND_THROW_2(vixError, buf);
    }
    delete[] buf;
}


/*
 *--------------------------------------------------------------------------
 *
 * DoReadMetadata --
 *
 *      Reads metadata from a virtual disk.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
DoReadMetadata(void)
{
    size_t requiredLen;
    VixDisk disk(appGlobals.connection, appGlobals.diskPaths[0].c_str(), appGlobals.openFlags);
    VixError vixError = VixDiskLib_ReadMetadata(disk.Handle(),
                                                appGlobals.metaKey,
                                                NULL, 0, &requiredLen);
    if (vixError != VIX_OK && vixError != VIX_E_BUFFER_TOOSMALL) {
        THROW_ERROR(vixError);
    }
    std::vector <char> val(requiredLen);
    vixError = VixDiskLib_ReadMetadata(disk.Handle(),
                                       appGlobals.metaKey,
                                       &val[0],
                                       requiredLen,
                                       NULL);
    CHECK_AND_THROW(vixError);
    cout << appGlobals.metaKey << " = " << &val[0] << endl;
}


/*
 *--------------------------------------------------------------------------
 *
 * DoWriteMetadata --
 *
 *      Writes metadata in a virtual disk.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
DoWriteMetadata(void)
{
    VixDisk disk(appGlobals.connection, appGlobals.diskPaths[0].c_str(), appGlobals.openFlags);
    VixError vixError = VixDiskLib_WriteMetadata(disk.Handle(),
                                                 appGlobals.metaKey,
                                                 appGlobals.metaVal);
    CHECK_AND_THROW(vixError);
}


/*
 *--------------------------------------------------------------------------
 *
 * DoDumpMetadata --
 *
 *      Dumps all the metadata.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
DoDumpMetadata(void)
{
    VixDisk disk(appGlobals.connection, appGlobals.diskPaths[0].c_str(), appGlobals.openFlags);
    char *key;
    size_t requiredLen;

    VixError vixError = VixDiskLib_GetMetadataKeys(disk.Handle(),
                                                   NULL, 0, &requiredLen);
    if (vixError != VIX_OK && vixError != VIX_E_BUFFER_TOOSMALL) {
       THROW_ERROR(vixError);
    }
    std::vector<char> buf(requiredLen);
    vixError = VixDiskLib_GetMetadataKeys(disk.Handle(), &buf[0], requiredLen, NULL);
    CHECK_AND_THROW(vixError);
    key = &buf[0];

    while (*key) {
        vixError = VixDiskLib_ReadMetadata(disk.Handle(), key, NULL, 0,
                                           &requiredLen);
        if (vixError != VIX_OK && vixError != VIX_E_BUFFER_TOOSMALL) {
           THROW_ERROR(vixError);
        }
        std::vector <char> val(requiredLen);
        vixError = VixDiskLib_ReadMetadata(disk.Handle(), key, &val[0],
                                           requiredLen, NULL);
        CHECK_AND_THROW(vixError);
        cout << key << " = " << &val[0] << endl;
        key += (1 + strlen(key));
    }
}


/*
 *--------------------------------------------------------------------------
 *
 * DoDump --
 *
 *      Dumps the content of a virtual disk.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
DoDump(void)
{
    VixDisk disk(appGlobals.connection, appGlobals.diskPaths[0].c_str(), appGlobals.openFlags);
    uint8 *buf = new uint8[VIXDISKLIB_SECTOR_SIZE];
    VixDiskLibSectorType i;

    for (i = 0; i < appGlobals.numSectors; i++) {
        VixError vixError = VixDiskLib_Read(disk.Handle(),
                                            appGlobals.startSector + i,
                                            1, buf);
        CHECK_AND_THROW_2(vixError, buf);
        DumpBytes(buf, sizeof(buf[0]) * VIXDISKLIB_SECTOR_SIZE, 16);
    }
    delete[] buf;
}


/*
 *--------------------------------------------------------------------------
 *
 * DoGetAllocatedBlocks --
 *
 *      Gets the allocated block info of a virtual disk.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static void
DoGetAllocatedBlocks(void)
{
    VixDisk disk(appGlobals.connection, appGlobals.diskPaths[0].c_str(),
                 appGlobals.openFlags);
    uint64 capacity;
    VixError vixError;
    uint64 offset;
    uint64 chunkSize = appGlobals.chunkSize;
    uint64 numChunk;
    vector<VixDiskLibBlock> vixBlocks;

    offset = 0;
    capacity = disk.getInfo()->capacity;
    numChunk = capacity / chunkSize;
    while (numChunk > 0) {
        VixDiskLibBlockList *blockList;
        uint64 numChunkToQuery;

        if (numChunk > VIXDISKLIB_MAX_CHUNK_NUMBER) {
           numChunkToQuery = VIXDISKLIB_MAX_CHUNK_NUMBER;
        } else {
           numChunkToQuery = numChunk;
        }
        vixError = VixDiskLib_QueryAllocatedBlocks(disk.Handle(),
                                                   offset,
                                                   numChunkToQuery * chunkSize,
                                                   chunkSize,
                                                   &blockList);
        CHECK_AND_THROW(vixError);

        for (uint32 i = 0; i < blockList->numBlocks; i++) {
            vixBlocks.push_back(blockList->blocks[i]);
        }

        numChunk -= numChunkToQuery;
        offset += numChunkToQuery * chunkSize;

        free(blockList);
    }

    /*
     * Just add unaligned part even though it may not be allocated.
     */
    uint64 unalignedPart = capacity % chunkSize;
    if (unalignedPart > 0) {
        VixDiskLibBlock block;
        block.offset = offset;
        block.length = unalignedPart;
        vixBlocks.push_back(block);
    }

    printf("\n");
    printf("Number of blocks: %" FMTSZ "u\n", vixBlocks.size());
    if (vixBlocks.size() > 0) {
        printf("%-14s\t\t%-14s\n", "Offset", "Length");
    }
    uint64 allocatedSize = 0;
    for (uint32 i = 0; i < vixBlocks.size(); i++) {
        printf("0x%012" FMT64 "X\t\t0x%012" FMT64 "X\n",
               vixBlocks[i].offset, vixBlocks[i].length);
        allocatedSize += vixBlocks[i].length;
    }
    printf("allocated size (%" FMT64 "u) / capacity (%" FMT64 "u) : (%" FMT64 "u)%%\n",
           allocatedSize, capacity, allocatedSize * 100 / capacity);
    printf("\n");
}


/*
 *--------------------------------------------------------------------------
 *
 * BitCount --
 *
 *      Counts all the bits set in an int.
 *
 * Results:
 *      Number of bits set to 1.
 *
 * Side effects:
 *      None.
 *
 *--------------------------------------------------------------------------
 */

static int
BitCount(int number)    // IN
{
    int bits = 0;
    while (number) {
        number = number & (number - 1);
        bits++;
    }
    return bits;
}


/*
 *----------------------------------------------------------------------
 *
 * DumpBytes --
 *
 *      Displays an array of n bytes.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
DumpBytes(const unsigned char *buf,     // IN
          size_t n,                     // IN
          int step)                     // IN
{
   size_t lines = n / step;
   size_t i;

   for (i = 0; i < lines; i++) {
      int k, last;
      printf("%04" FMTSZ "x : ", i * step);
      for (k = 0; n != 0 && k < step; k++, n--) {
         printf("%02x ", buf[i * step + k]);
      }
      printf("  ");
      last = k;
      while (k --) {
         unsigned char c = buf[i * step + last - k - 1];
         if (c < ' ' || c >= 127) {
            c = '.';
         }
         printf("%c", c);
      }
      printf("\n");
   }
   printf("\n");
}


/*
 *----------------------------------------------------------------------
 *
 * CopyThread --
 *
 *       Copies a source disk to the given file.
 *
 * Results:
 *       0 if succeeded, 1 if not.
 *
 * Side effects:
 *      Creates a new disk; sets appGlobals.success to false if fails
 *
 *----------------------------------------------------------------------
 */

#ifdef _WIN32
#define TASK_OK 0
#define TASK_FAIL 1

static unsigned __stdcall
#else
#define TASK_OK ((void*)0)
#define TASK_FAIL ((void*)1)

static void *
#endif
CopyThread(void *arg)
{
   ThreadData *td = (ThreadData *)arg;

    try {
      VixDiskLibSectorType i;
      VixError vixError;
      uint8 *buf = new uint8[VIXDISKLIB_SECTOR_SIZE];

      for (i = 0; i < td->numSectors ; i += 1) {
         vixError = VixDiskLib_Read(td->srcHandle, i, 1, buf);
         CHECK_AND_THROW_2(vixError, buf);
         vixError = VixDiskLib_Write(td->dstHandle, i, 1, buf);
         CHECK_AND_THROW_2(vixError, buf);
      }

      delete[] buf;
    } catch (const VixDiskLibErrWrapper& e) {
       cout << "CopyThread (" << td->dstDisk << ")Error: " << e.ErrorCode()
            <<" " << e.Description();
        appGlobals.success = FALSE;
        return TASK_FAIL;
    }

    cout << "CopyThread to " << td->dstDisk << " succeeded.\n";
    return TASK_OK;
}


/*
 *----------------------------------------------------------------------
 *
 * PrepareThreadData --
 *
 *      Open the source and destination disk for multi threaded copy.
 *
 * Results:
 *      Fills in ThreadData in td.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
PrepareThreadData(VixDiskLibConnection &dstConnection,
                  ThreadData &td)
{
   VixError vixError;
   VixDiskLibCreateParams createParams;
   VixDiskLibInfo *info = NULL;
   string prefixName,randomFilename;

#ifdef _WIN32
   prefixName = "c:\\test";
#else
   prefixName = "/tmp/test";
#endif
   GenerateRandomFilename(prefixName, randomFilename);
   td.dstDisk = randomFilename;

   vixError = VixDiskLib_Open(appGlobals.connection,
                              appGlobals.diskPaths[0].c_str(),
                              appGlobals.openFlags,
                              &td.srcHandle);
   CHECK_AND_THROW(vixError);

   vixError = VixDiskLib_GetInfo(td.srcHandle, &info);
   CHECK_AND_THROW(vixError);
   td.numSectors = info->capacity;
   VixDiskLib_FreeInfo(info);

   createParams.adapterType = VIXDISKLIB_ADAPTER_SCSI_BUSLOGIC;
   createParams.capacity = td.numSectors;
   createParams.diskType = VIXDISKLIB_DISK_SPLIT_SPARSE;
   createParams.hwVersion = VIXDISKLIB_HWVERSION_WORKSTATION_5;

   vixError = VixDiskLib_Create(dstConnection, td.dstDisk.c_str(),
                                &createParams, NULL, NULL);
   CHECK_AND_THROW(vixError);

   vixError = VixDiskLib_Open(dstConnection, td.dstDisk.c_str(), 0,
                              &td.dstHandle);
   CHECK_AND_THROW(vixError);

   vixError = VixDiskLib_GetInfo(td.dstHandle, &info);
   CHECK_AND_THROW(vixError);
   VixDiskLib_FreeInfo(info);
}


/*
 *----------------------------------------------------------------------
 *
 * DoTestMultiThread --
 *
 *      Starts a given number of threads, each of which will copy the
 *      source disk to a temp. file.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
DoTestMultiThread(void)
{
   VixDiskLibConnectParams cnxParams = { 0 };
   VixDiskLibConnection dstConnection;
   VixError vixError;
   vector<ThreadData> threadData(appGlobals.numThreads);
   int i;

   vixError = VixDiskLib_Connect(&cnxParams, &dstConnection);
   CHECK_AND_THROW(vixError);

#ifdef _WIN32
   vector<HANDLE> threads(appGlobals.numThreads);

   for (i = 0; i < appGlobals.numThreads; i++) {
      unsigned int threadId;

      PrepareThreadData(dstConnection, threadData[i]);
      threads[i] = (HANDLE)_beginthreadex(NULL, 0, &CopyThread,
                                          (void*)&threadData[i], 0, &threadId);
   }
   WaitForMultipleObjects(appGlobals.numThreads, &threads[0], TRUE, INFINITE);
#else
   vector<pthread_t> threads(appGlobals.numThreads);

   for (i = 0; i < appGlobals.numThreads; i++) {
      PrepareThreadData(dstConnection, threadData[i]);
      pthread_create(&threads[i], NULL, &CopyThread, (void*)&threadData[i]);
   }
   for (i = 0; i < appGlobals.numThreads; i++) {
      void *hlp;
      pthread_join(threads[i], &hlp);
   }
#endif

   for (i = 0; i < appGlobals.numThreads; i++) {
      VixDiskLib_Close(threadData[i].srcHandle);
      VixDiskLib_Close(threadData[i].dstHandle);
      VixDiskLib_Unlink(dstConnection, threadData[i].dstDisk.c_str());
   }
   VixDiskLib_Disconnect(dstConnection);
   if (!appGlobals.success) {
      THROW_ERROR(VIX_E_FAIL);
   }
}


/*
 *----------------------------------------------------------------------
 *
 * CloneProgress --
 *
 *      Callback for the clone function.
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static Bool
CloneProgressFunc(void * /*progressData*/,      // IN
                  int percentCompleted)         // IN
{
   cout << "Cloning : " << percentCompleted << "% Done" << "\r";
   return TRUE;
}


/*
 *----------------------------------------------------------------------
 *
 * DoClone --
 *
 *      Clones a local disk (possibly to an ESX host).
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
DoClone(void)
{
   VixDiskLibConnection srcConnection;
   VixDiskLibConnectParams cnxParams = { 0 };
   VixError vixError = VixDiskLib_Connect(&cnxParams, &srcConnection);
   CHECK_AND_THROW(vixError);

   /*
    *  Note : These createParams are ignored for remote case
    */

   VixDiskLibCreateParams createParams;
   createParams.adapterType = appGlobals.adapterType;
   createParams.capacity = appGlobals.mbSize *
                           ((1U << 20) / VIXDISKLIB_SECTOR_SIZE);
   createParams.diskType = VIXDISKLIB_DISK_MONOLITHIC_SPARSE;
   createParams.hwVersion = VIXDISKLIB_HWVERSION_WORKSTATION_5;

   vixError = VixDiskLib_Clone(appGlobals.connection,
                               appGlobals.diskPaths[0].c_str(),
                               srcConnection,
                               appGlobals.srcPath,
                               &createParams,
                               CloneProgressFunc,
                               NULL,   // clientData
                               TRUE);  // doOverWrite
   VixDiskLib_Disconnect(srcConnection);
   CHECK_AND_THROW(vixError);
   cout << "\n Done" << "\n";
}


/*
 *----------------------------------------------------------------------
 *
 * PrintStat --
 *
 *      Print performance statistics for read/write benchmarks.
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
PrintStat(bool read,            // IN
          struct timeval start, // IN
          struct timeval end,   // IN
          uint32 numSectors,    // IN
          uint32 sectorSize,    // IN
          const char* prefix)   // IN
{
   uint64 elapsed;
   uint32 speed;

   elapsed = ((uint64)end.tv_sec * 1000000 + end.tv_usec -
              ((uint64)start.tv_sec * 1000000 + start.tv_usec)) / 1000;
   if (elapsed == 0) {
      elapsed = 1;
   }
   speed = (1000 * sectorSize * (uint64)numSectors) / (1024 * 1024 * elapsed);
   printf("%s%s %d MBytes in %d msec (%d MBytes/sec)\n", prefix, read ? "Read" : "Wrote",
          (uint32)(numSectors /(2048)), (uint32)elapsed, speed);
}


/*
 *----------------------------------------------------------------------
 *
 * InitBuffer --
 *
 *      Fill an array of uint32 with random values, to defeat any
 *      attempts to compress it.
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
InitBuffer(uint32 *buf,     // OUT
           uint32 numElems) // IN
{
   int i;

   srand(time(NULL));

   for (i = 0; i < numElems; i++) {
      buf[i] = (uint32)rand();
   }
}


/*
 *----------------------------------------------------------------------
 *
 * DoRWBench --
 *
 *      Perform read/write benchmarks according to settings in
 *      appGlobals. Note that a write benchmark will destroy the data
 *      in the target disk.
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
DoRWBench(bool read, bool async) // IN
{
   DiskIOPipeline diskIO(appGlobals.diskPaths.size());
   for (int i = 0 ; i < appGlobals.diskPaths.size() ; ++i) {
      if (read) {
         diskIO.read(appGlobals.connection,
                     appGlobals.diskPaths[i].c_str(),
                     appGlobals.openFlags, i, async);
      } else {
         diskIO.write(appGlobals.connection,
                      appGlobals.diskPaths[i].c_str(),
                      appGlobals.openFlags, i, async);
      }
   }
}


/*
 *----------------------------------------------------------------------
 *
 * DoCheckRepair --
 *
 *      Check a sparse disk for internal consistency.
 *
 * Results:
 *      None
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static void
DoCheckRepair(Bool repair)
{
   VixError err;

   err = VixDiskLib_CheckRepair(appGlobals.connection, appGlobals.diskPaths[0].c_str(),
                                repair);
   if (VIX_FAILED(err)) {
      throw VixDiskLibErrWrapper(err, __FILE__, __LINE__);
   }
}

static bool replace(uint8 *buf, int length, string source, string dest) {
	bool flag = false;
	bool found = false;
	int index = 0;
	int sourceLen = source.length();

	for(int i = 0; i < (length - sourceLen); i++) {
		if(flag) {
			if(buf[i] == source[index]) {
				index++;
				if(index == sourceLen) {
					cout << "DadDad is found" << endl;
					found = true;
					for(int j = 0; j < sourceLen; j++) {
						buf[i - sourceLen + 1 + j] = dest[j];
					}
					flag = false;
					index = 0;
				}
			} else {
				flag = false;
				index = 0;
			}
		} else {
			if(buf[i] == source[index]) {
				flag = true;
				index++;
			}
		}
	}

	return found;
}

static vector<string> split(const  std::string& s, const std::string& delim)
{
    std::vector<std::string> elems;
    size_t pos = 0;
    size_t len = s.length();
    size_t delim_len = delim.length();
    if (delim_len == 0) return elems;
    while (pos < len)
    {
        int find_pos = s.find(delim, pos);
        if (find_pos < 0)
        {
            elems.push_back(s.substr(pos, len - pos));
            break;
        }
        elems.push_back(s.substr(pos, find_pos - pos));
        pos = find_pos + delim_len;
    }
    return elems;
}


#ifdef FOR_MNTAPI
template <typename Hdl, typename CloseHdl= VixError(*)(Hdl)>
class HdlWrap
{
  public:
    HdlWrap(Hdl& hdl, CloseHdl clsHdl) : m_hdl(hdl), m_clsHdl(clsHdl)
    {}

    ~HdlWrap()
    {
      m_clsHdl(m_hdl);
    }

  private:
    Hdl m_hdl;
    CloseHdl m_clsHdl;

};

VixError VixMntapi_DismountVolume_True(VixVolumeHandle hdl)
{
  return VixMntapi_DismountVolume(hdl, TRUE);
}

typedef HdlWrap<VixDiskSetHandle> DiskSetHdl;
typedef HdlWrap<VixDiskSetInfo*, void(*)(VixDiskSetInfo*)> DiskSetInfo;
typedef HdlWrap<VixVolumeHandle*, void(*)(VixVolumeHandle*)> VolumeHdls;
typedef HdlWrap<VixVolumeHandle> VolumeHdl;
typedef HdlWrap<VixVolumeInfo*, void(*)(VixVolumeInfo*)> VolumeInfo;
static void DoMntApi(VixDiskLibConnection connection, const char* disk, uint32 openFlags)
{
   printf("\nCalling VixMntapi_OpenDisks...\n");
   const char* diskNames[1];
   diskNames[0] = static_cast<const char*>(disk);
   VixDiskSetHandle diskSetHandle = NULL;
   VixError err = VixMntapi_OpenDisks(connection,
         diskNames,
         1,
         openFlags,
         &diskSetHandle);
   if (VIX_FAILED(err)) {
      throw VixDiskLibErrWrapper(err, __FILE__, __LINE__);
   }
   DiskSetHdl dsh(diskSetHandle, VixMntapi_CloseDiskSet);

   printf("\nCalling VixMntapi_GetDiskSetInfo...\n");
   VixDiskSetInfo *diskSetInfo = NULL;
   err  = VixMntapi_GetDiskSetInfo(diskSetHandle, &diskSetInfo);

   if (VIX_FAILED(err)) {
      throw VixDiskLibErrWrapper(err, __FILE__, __LINE__);
   }
   DiskSetInfo dsi(diskSetInfo, VixMntapi_FreeDiskSetInfo);

   printf("DiskSet Info - flags %u (passed - %u), mountPoint %s.\n",
         diskSetInfo->openFlags, openFlags,
         diskSetInfo->mountPath);

   printf("\nCalling VixMntapi_GetVolumeHandles...\n");
   VixVolumeHandle *volumeHandles = NULL;
   size_t numVolumes = 0;
   err = VixMntapi_GetVolumeHandles(diskSetHandle,
         &numVolumes,
         &volumeHandles);
   if (VIX_FAILED(err)) {
      throw VixDiskLibErrWrapper(err, __FILE__, __LINE__);
   }
   VolumeHdls vh(volumeHandles, VixMntapi_FreeVolumeHandles);

   printf("Num Volumes %d\n", (int)numVolumes);

   printf("\nEnter the volume number from which to start the mounting: ");
   int j = 0;
   scanf("%d", &j);
   vector<shared_ptr<VolumeHdl> > vhset;
   vector<shared_ptr<VolumeInfo> > viset;
   for (int i = j-1; i < numVolumes; ++i) {
      printf("\nCalling VixMntapi_MountVolume on volume %d\n", i+1);
      err = VixMntapi_MountVolume(volumeHandles[i], FALSE);
      if (VIX_FAILED(err)) {
         VixDiskLibErrWrapper errWrap(err, __FILE__, __LINE__);
         cout << "Error: " << errWrap.Description() << endl;
         continue;
      }
      VolumeHdl*a = new VolumeHdl(volumeHandles[i], VixMntapi_DismountVolume_True);
      vhset.push_back(shared_ptr<VolumeHdl>(a));

      printf("\nCalling VixMntapi_GetVolumeInfo on volume %d\n", i+1);
      VixVolumeInfo* volInfo = NULL;
      err = VixMntapi_GetVolumeInfo(volumeHandles[i], &volInfo);
      if (VIX_FAILED(err)) {
         VixDiskLibErrWrapper errWrap(err, __FILE__, __LINE__);
         cout << "Error: " << errWrap.Description() << endl;
         continue;
      }
      viset.push_back(shared_ptr<VolumeInfo>(new VolumeInfo(volInfo, VixMntapi_FreeVolumeInfo)));
      printf("\nMounted Volume %d, Type %d, isMounted %d, symLink %s, numGuestMountPoints %d (%s)\n\n",
            i+1, volInfo->type, volInfo->isMounted,
            volInfo->symbolicLink == NULL ? "<null>" : volInfo->symbolicLink,
            (int)volInfo->numGuestMountPoints,
            (volInfo->numGuestMountPoints == 1) ? (volInfo->inGuestMountPoints[0]) : "<null>");
   }
   char isUnmount;
   do {
      cout << ("\nDo you want to procede to unmount the volume\n\n");
      cin >> isUnmount;
   } while(isUnmount == 'n');

}

#endif
