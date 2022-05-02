// PassUnlock.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <clocale>
#include <cstring>
#include <memory.h>
#include <iostream>
#include <vector>
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <chrono>
#include <iomanip>

#pragma warning(disable: 26812)
#include "gpg-error.h"
#include "gpgme.h"
#pragma warning(default: 26812)


#define DEBUG_VERBOSE 0

//////////////////////////////////////////////////////////////////////////
// Function forwarding
//////////////////////////////////////////////////////////////////////////

void GetAllWindowsFromProcessID(DWORD dwProcessID, std::vector <HWND>& vhWnds);
bool FindTargetWindow(const WCHAR* exeName, const WCHAR* winTitle, HWND& windowHandle);
bool FindTargetProcess(const WCHAR* exeName);
bool PostPhrase(HWND targetWindow, const WCHAR* phrase);
bool DecryptData(const char* encrypted_data, char* intermediate_buffer, const int buffer_size);


//////////////////////////////////////////////////////////////////////////
// Windows grabbing and messaging functions
//////////////////////////////////////////////////////////////////////////

// Adapted from https://stackoverflow.com/questions/11711417/get-hwnd-by-process-id-c
void GetAllWindowsFromProcessID(DWORD dwProcessID, std::vector <HWND>& vhWnds)
{
	// find all hWnds (vhWnds) associated with a process id (dwProcessID)
	HWND hCurWnd = NULL;
	do
	{
		hCurWnd = FindWindowEx(NULL, hCurWnd, NULL, NULL);
		DWORD dwProcID = 0;
		GetWindowThreadProcessId(hCurWnd, &dwProcID);
		if (dwProcID == dwProcessID)
		{
			vhWnds.push_back(hCurWnd);  // add the found hCurWnd to the vector
			if constexpr (DEBUG_VERBOSE)
			{
				std::wcout << L"Found hWnd 0x" << std::hex << hCurWnd << std::dec << std::endl;
			}
		}
	} while (hCurWnd != NULL);
}

// Adapted from https://stackoverflow.com/questions/2397578/how-to-get-the-executable-name-of-a-window
bool FindTargetWindow(const WCHAR* exeName, const WCHAR* winTitle, HWND& windowHandle)
{
	HWND hwnd;//window handle
	DWORD pid;//process pid
	hwnd = FindWindow(NULL, NULL);//find any window
	PROCESSENTRY32 entry;//process structure containing info about processes
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//get processes
	if (hwnd != 0)
	{
		GetWindowThreadProcessId(hwnd, &pid);//get found window pid
	}

	if (Process32First(snapshot, &entry) == TRUE)//start listing processes
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_wcsicmp(entry.szExeFile, exeName) == 0)
			{
				if constexpr (DEBUG_VERBOSE)
				{
					std::wcout << L"FindTargetWindow() Found: " << entry.szExeFile << std::endl;
				}
				std::vector<HWND> vHwnd; // List of handles
				GetAllWindowsFromProcessID(entry.th32ProcessID, vHwnd);

				for (HWND hwnd : vHwnd)
				{
					constexpr int window_title_max_size = 256;
					WCHAR WindowTitle[window_title_max_size];
					memset(WindowTitle, '\0', sizeof(WCHAR) * window_title_max_size);
					SendMessage(hwnd, WM_GETTEXT, sizeof(WindowTitle) / sizeof(WindowTitle[0]), LPARAM(WindowTitle));

					if (_wcsicmp(WindowTitle, winTitle) == 0)
					{
						if constexpr (DEBUG_VERBOSE)
						{
							std::wcout << L"Found window with title " << WindowTitle << L" - hWnd: 0x" << std::hex << hwnd << std::dec << std::endl;
						}
						windowHandle = hwnd;
						return true;
					}
				}

				if constexpr (DEBUG_VERBOSE)
				{
					std::wcout << L"Window count: " << vHwnd.size() << std::endl;
				}
			}
		}
	}

	return false;
}


// Adapted from https://stackoverflow.com/questions/2397578/how-to-get-the-executable-name-of-a-window
// 
// Notes for the future: The reason why this exists and it's mostly a duplicated version of FindTargetWindow(),
// looking like it's just hurting the DRY principle, is that this stops as soon as it finds a matching process,
// while FindTargetWindow() goes through all processes with given name. This way, we can get the all the windows
// from all the processes with given name.
//
bool FindTargetProcess(const WCHAR* exeName)
{
	HWND hwnd; //window handle
	DWORD pid; //process pid
	hwnd = FindWindow(NULL, NULL); //find any window
	PROCESSENTRY32 entry; //process structure containing info about processes
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//get processes
	if (hwnd != 0)
	{
		GetWindowThreadProcessId(hwnd, &pid);//get found window pid
	}

	if (Process32First(snapshot, &entry) == TRUE)//start listing processes
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_wcsicmp(entry.szExeFile, exeName) == 0)
			{
				if constexpr (DEBUG_VERBOSE)
				{
					std::wcout << L"FindTargetProcess() Found: " << entry.szExeFile << std::endl;
				}
				return true;
			}
		}
	}

	return false;
}

bool PostPhrase(HWND targetWindow, const WCHAR* phrase)
{
	const int phraseLen = wcslen(phrase);

	for (int i = 0; i < phraseLen; ++i)
	{
		if (!PostMessageW(targetWindow, WM_CHAR, phrase[i], 0))
			return false;

		Sleep(10);
	}

	SendMessage(targetWindow, WM_KEYDOWN, VK_RETURN, 0);
	Sleep(10);
	SendMessage(targetWindow, WM_KEYUP, VK_RETURN, 0);

	return true;
}

//////////////////////////////////////////////////////////////////////////
// Gpgme Functions
//////////////////////////////////////////////////////////////////////////

// This macro avoid repeating a large chunk of boilerplate code.
#define RUN_ON_PREVIOUS_SUCCESS(condition, error_control, function) 																\
	do																																\
	{																																\
		if(condition)																												\
		{																															\
			(error_control) = (function);																							\
			if (error_control)																										\
			{																														\
				if constexpr (DEBUG_VERBOSE)																						\
				{																													\
					fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource(condition), gpgme_strerror(condition));	\
				}																													\
				condition = false;																									\
			}																														\
		}																															\
	}																																\
	while(0)

bool DecryptData(const char* encrypted_data, char* intermediate_buffer, const int buffer_size)
{
	constexpr gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
	gpgme_error_t err;
	gpgme_ctx_t ctx = nullptr;
	gpgme_data_t in = nullptr;
	gpgme_data_t out = nullptr;
	gpgme_decrypt_result_t result;

	bool success = true;

	// Init gpgme
	if (!gpgme_check_version(NULL))
	{
		if constexpr (DEBUG_VERBOSE) fprintf(stderr, "%s:%d: Error initializing gpgme\n", __FILE__, __LINE__);
		success = false;
	}
	setlocale(LC_ALL, "");
	gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

	RUN_ON_PREVIOUS_SUCCESS(success, err, gpgme_engine_check_version(protocol));
	RUN_ON_PREVIOUS_SUCCESS(success, err, gpgme_new(&ctx));
	RUN_ON_PREVIOUS_SUCCESS(success, err, gpgme_set_protocol(ctx, protocol));
	RUN_ON_PREVIOUS_SUCCESS(success, err, gpgme_data_new(&out));
	RUN_ON_PREVIOUS_SUCCESS(success, err, gpgme_data_new_from_mem(&in, encrypted_data, strlen(encrypted_data), 1));
	RUN_ON_PREVIOUS_SUCCESS(success, err, gpgme_data_set_encoding(in, GPGME_DATA_ENCODING_ARMOR));
	RUN_ON_PREVIOUS_SUCCESS(success, err, gpgme_op_decrypt(ctx, in, out));
	RUN_ON_PREVIOUS_SUCCESS(success, err, gpgme_data_set_encoding(in, GPGME_DATA_ENCODING_ARMOR));

	result = gpgme_op_decrypt_result(ctx);
	if (result)
	{
		memset(intermediate_buffer, 0, buffer_size);
		gpgme_data_seek(out, 0, SEEK_SET);
		if (gpgme_data_read(out, intermediate_buffer, buffer_size - 1) < 1)
		{
			fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, gpgme_strsource(err), gpgme_strerror(err));
			success = false;
		}
	}
	else
	{
		success = false;
	}

	gpgme_data_release(in);
	gpgme_data_release(out);
	gpgme_release(ctx);

	return success;
}

#undef RUN_ON_PREVIOUS_SUCCESS

//////////////////////////////////////////////////////////////////////////
// Entry point
//////////////////////////////////////////////////////////////////////////

int main()
{
	// Password buffer
	constexpr int buffer_size = 2048;
	char intermediate_buffer[buffer_size];
	char pass_buffer[buffer_size];

	// 1password Application name and target window
	const wchar_t app_name[] = L"1password.exe";
	const wchar_t window_title[] = L"Unlock";

	constexpr int unlock_timeout = 15;
	constexpr int sleep_amount = 250;
	constexpr float sleep_update_ratio = 1000.f / sleep_amount;

	// Double encode the password data, for the peace of mind.
	constexpr char encrypted_data[] = "-----BEGIN PGP MESSAGE-----\n"
		"\n"
		"ADD_DATA_HERE1\n"
		"ADD_DATA_HERE2\n"
		"ADD_DATA_HERE3\n"
		"ADD_DATA_HERE4\n"
		"ADD_DATA_HERE5\n"
		"ADD_DATA_HERE6\n"
		"ADD_DATA_HERE7\n"
		"ADD_DATA_HERE8\n"
		"ADD_DATA_HERE9\n"
		"ADD_DATA_HERE10\n"
		"ADD_DATA_HERE11\n"
		"ADD_DATA_HERE12\n"
		"ADD_DATA_HERE13\n"
		"ADD_DATA_HERE14\n"
		"ADD_DATA_HERE15\n"
		"ADD_DATA_HERE16\n"
		"ADD_DATA_HERE17\n"
		"-----END PGP MESSAGE-----\n";

	// Only proceed if 1password is open and running.
	{
		if (!FindTargetProcess(app_name))
		{
			std::wcout << L"Unable to find process for: " << app_name << std::endl;
			return 1;
		}
	}

	bool success = DecryptData(encrypted_data, intermediate_buffer, buffer_size);

	if (!success)
	{
		std::wcout << L"Error decrypting data." << std::endl;
		return 1; // error
	}

	std::wcout << L"GPG initial decrypt successful." << std::endl;

	// Focus 1password window and enter the password
	HWND onePassUnlockWindow = nullptr;
	std::wcout << L"Looking for 1Password unlock window... " << unlock_timeout;

	std::chrono::time_point<std::chrono::steady_clock> start = std::chrono::steady_clock::now();
	std::chrono::duration<double> diff;
	int refresh = 0;
	do
	{
		Sleep(sleep_amount);	//reduce cpu usage

		// Do not re-use the process id from above, since it might change if a browser was opened.
		// Sometimes 1password restarts itself when a browser opens for updates.
		if (FindTargetWindow(app_name, window_title, onePassUnlockWindow))
		{
			if constexpr (DEBUG_VERBOSE)
			{
				std::wcout << L"\n\nFound Window with handle: 0x" << std::hex << onePassUnlockWindow << std::dec << std::endl;
			}
			break;
		}

		diff = std::chrono::steady_clock::now() - start;
		if (++refresh >= sleep_update_ratio)
		{
			if constexpr (!DEBUG_VERBOSE)
			{
				std::wcout << L"\b\b" << std::setw(2) << unlock_timeout - static_cast<int>(diff.count());
			}
			refresh = 0;
		}

	} while (diff.count() < unlock_timeout);

	std::wcout << std::endl;

	if constexpr (DEBUG_VERBOSE)
	{
		std::wcout << L"Stage 2..." << std::endl;
	}

	// Stage 2;
	success = DecryptData(intermediate_buffer, pass_buffer, buffer_size);
	if (!success)
	{
		std::wcout << L"Error decrypting intermediate data." << std::endl;
		return 1; // error
	}

	if constexpr (DEBUG_VERBOSE)
	{
		std::wcout << L"Unlocking..." << std::endl;
	}

	if (onePassUnlockWindow)
	{
		// Gnu tools works in UTF-8, while windows works in UTF-16. Do the conversion.
		success = false;
		const size_t len = strlen(pass_buffer) + 1;
		if (wchar_t* utf16buffer = new wchar_t[len])
		{
			setlocale(LC_ALL, "");
			size_t outSize;
			mbstowcs_s(&outSize, utf16buffer, len, pass_buffer, len - 1); // C4996
			success = PostPhrase(onePassUnlockWindow, utf16buffer);
			delete[](utf16buffer);
		}
	}
	else
	{
		std::wcout << L"Unable to locate target window." << std::endl;
		return 1;
	}

	if (!success)
	{
		std::wcout << L"Failed while attempting to unlock application." << std::endl;
		return 1;
	}
	
	return 0;
}
