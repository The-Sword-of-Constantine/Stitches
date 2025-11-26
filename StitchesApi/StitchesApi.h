// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 STITCHESAPI_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// STITCHESAPI_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifdef STITCHESAPI_EXPORTS
#define STITCHESAPI_API __declspec(dllexport)
#else
#define STITCHESAPI_API __declspec(dllimport)
#endif

#ifndef _C_API
namespace StitchesApi
{
#define STITCHESAPI_NS	StitchesApi::
#define STITCHESAPI_CC	
#else // _C_API
#define NFAPI_CC __cdecl
#define NFAPI_NS
#ifdef __cplusplus
extern "C"
{
#endif
#endif // _C_API


	template <typename T>
	class Singleton {
	public:
		Singleton(const Singleton&) = delete;
		Singleton& operator=(const Singleton&) = delete;

		static T& getInstance()
		{
			std::call_once(_InitInstanceFlag, []() {_Instance.reset(new T()); });
			return *_Instance;
		}

	protected:
		Singleton() = default;
		virtual ~Singleton() = default;

	private:
		static std::once_flag		_InitInstanceFlag;
		static std::unique_ptr<T>	_Instance;	
	};

	template <typename T>
	std::once_flag Singleton<T>::_InitInstanceFlag;

	template <typename T>
	std::unique_ptr<T> Singleton<T>::_Instance = nullptr;


	constexpr ULONG MAX_THREAD_POOL = 64;

	struct IO_MESSAGE
	{
		OVERLAPPED OverLapped;

		FILTER_MESSAGE_HEADER FilterMessageHander;

		UCHAR Data[65535];
	};




	// 此类是从 dll 导出的
	class STITCHESAPI_API CStitchesApi : public Singleton<CStitchesApi>
	{
	public:
		CStitchesApi(void);
		CStitchesApi(std::wstring ServiceName)
		{
			memcpy(m_wstrServiceName, ServiceName.c_str(), ServiceName.length() * sizeof(WCHAR));
		}

		BOOLEAN
		STITCHESAPI_CC
		InstallDriver();

		BOOLEAN
		STITCHESAPI_CC
		UninstallDriver();

		BOOLEAN
		STITCHESAPI_CC
		OpenDevice();

		BOOLEAN STITCHESAPI_CC AddTrustProcess(CONST std::wstring& ProcessPath);
		BOOLEAN STITCHESAPI_CC DelTrustProcess(CONST std::wstring& ProcessPath);
		BOOLEAN STITCHESAPI_CC AddProtectProcess(CONST std::wstring& ProcessPath);
		BOOLEAN STITCHESAPI_CC DelProtectProcess(CONST std::wstring& ProcessPath);
		BOOLEAN STITCHESAPI_CC AddProtectFile(CONST std::wstring& ProcessPath);
		BOOLEAN STITCHESAPI_CC DelProtectFile(CONST std::wstring& ProcessPath);
		BOOLEAN STITCHESAPI_CC AddProtectRegistry(CONST std::wstring& RegistryPath);
		BOOLEAN STITCHESAPI_CC DelProtectRegistry(CONST std::wstring& RegistryPath);


		BOOLEAN STITCHESAPI_CC SetHookDllPath(CONST std::wstring& x64dll, CONST std::wstring& x86dll);

		BOOLEAN STITCHESAPI_CC AdjustPriviledges();

		BOOLEAN STITCHESAPI_CC HandleIoData();


	protected:
		BOOLEAN
		STITCHESAPI_CC
		InstallMinifilterDriver(
			CONST std::wstring& DriverPath,
			CONST std::wstring& InstanceName,
			CONST std::wstring& Altitude,
			BOOLEAN AutoStart = TRUE);


	public:
		HANDLE const GetIocpHandle ()
		{
			return m_hIocp;
		}

		HANDLE const GetCommunicationPort()
		{
			return m_hCommunicationPort;
		}


	private:
		WCHAR	m_wstrServiceName[MAX_PATH]{};

		WCHAR	m_wstrPortName[MAX_PATH]{};
		HANDLE	m_hCommunicationPort{ nullptr };

		HANDLE	m_hIocp{ nullptr };
		ULONG	m_nThreadPoolSize{ 0 };
		ULONG	m_ThreadPoolArray[MAX_THREAD_POOL]{ 0 };


	};


//STITCHESAPI_API BOOLEAN STITCHESAPI_CC AddTrustProcess(CONST std::wstring& ProcessPath);


#ifdef __cplusplus
}
#endif

