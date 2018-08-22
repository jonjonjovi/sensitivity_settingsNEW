#include <windows.h>
#include <atlbase.h>
#include <winternl.h>
#include <ntstatus.h>
#include<iostream>
#include <cstdlib>
#include<string>
#pragma comment(lib, "ntdll")

#include <system_error>

#ifndef FILE_CS_FLAG_CASE_SENSITIVE_DIR

#define FileCaseSensitiveInformation (FILE_INFORMATION_CLASS)71
#define FILE_CS_FLAG_CASE_SENSITIVE_DIR 0x00000001

typedef struct {
	ULONG Flags;
} FILE_CASE_SENSITIVE_INFORMATION, *PFILE_CASE_SENSITIVE_INFORMATION;

#endif

extern "C" NTSTATUS NTSYSAPI NTAPI NtSetInformationFile(
	_In_  HANDLE                 FileHandle,
	_Out_ PIO_STATUS_BLOCK       IoStatusBlock,
	_In_  PVOID                  FileInformation,
	_In_  ULONG                  Length,
	_In_  FILE_INFORMATION_CLASS FileInformationClass);

extern "C" NTSTATUS NTSYSAPI NTAPI NtQueryInformationFile(
	_In_  HANDLE                 FileHandle,
	_Out_ PIO_STATUS_BLOCK       IoStatusBlock,
	_In_  PVOID                  FileInformation,
	_In_  ULONG                  Length,
	_In_  FILE_INFORMATION_CLASS FileInformationClass);

int main(int argc,char* argv[])
{

	std::string val = argv[2];
	std::wstring stemp = std::wstring(val.begin(), val.end());
	LPCWSTR path = stemp.c_str();
	LPCSTR path_LPCSTR = val.c_str();
	
	HANDLE d = CreateFile(
		path_LPCSTR,
		FILE_WRITE_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
		nullptr);


	if (d == INVALID_HANDLE_VALUE)
	{
		std::cout << "Create File: " << GetLastError() <<std::endl;
		return EXIT_FAILURE;
	}
	
	IO_STATUS_BLOCK iob;
	//FILE_CASE_SENSITIVE_INFORMATION file_cs = { FILE_CS_FLAG_CASE_SENSITIVE_DIR };

	FILE_CASE_SENSITIVE_INFORMATION file_cs;
	std::string action = argv[1];
	

	if (action == "Query" || action == "query")
	{
		//IO_STATUS_BLOCK iob;
		//FILE_CASE_SENSITIVE_INFORMATION file_cs = { FILE_CS_FLAG_CASE_SENSITIVE_DIR };

		//FILE_CASE_SENSITIVE_INFORMATION file_cs;
		NTSTATUS status = NtQueryInformationFile(
			d,
			&iob,
			&file_cs,
			sizeof file_cs,
			FileCaseSensitiveInformation);

		/*NTSTATUS status = NtSetInformationFile(
			d,
			&iob,
			&file_cs,
			sizeof file_cs,
			FileCaseSensitiveInformation);*/
		switch (file_cs.Flags)
		{
		case 0:
			std::cout << "Case sensitivity is disabled" << std::endl;
			break;
		case 1:
			std::cout << "Case sensitivity is enabled" << std::endl;
			break;
		}
		//std::cout << file_cs.Flags << std::endl;
		if (NT_ERROR(status))
		{
			const auto err = ::RtlNtStatusToDosError(status);

			std::cout << "NtSetInformationFile failed: " << std::system_category().message(err).c_str() << std::endl;
			return EXIT_FAILURE;
		}

	}
	else if (action == "Set" || action == "set")
	{
		if (argv[3] != NULL)
		{
			//std::string set_v = argv[3];
			if (1)
			{
				FILE_CASE_SENSITIVE_INFORMATION file_cs = { FILE_CS_FLAG_CASE_SENSITIVE_DIR };
			}
			/*else if (set_v == "Disable" || set_v == "disable")
			{
				FILE_CASE_SENSITIVE_INFORMATION file_cs = {0};
			}
			else
			{
				std::cout << "Invalid parameters" << std::endl;
				return EXIT_FAILURE;
			}*/

			NTSTATUS status = NtSetInformationFile(
				d,
				&iob,
				&file_cs,
				sizeof file_cs,
				FileCaseSensitiveInformation);

			if (NT_ERROR(status))
			{
				const auto err = ::RtlNtStatusToDosError(status);

				std::cout << "NtSetInformationFile failed: " << std::system_category().message(err).c_str() << std::endl;
				return EXIT_FAILURE;
			}
		}
	}
	else 
	{
		std::cout <<"Tool for editing case sensitivity"<<std::endl;
	}
}