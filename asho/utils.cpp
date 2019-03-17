#include "stdafx.h"

std::string AddressToHexString(const DWORD_PTR address)
{
	char hexAddress[2 + 2 * sizeof(DWORD_PTR) + 1]{};
#if defined(_WIN64)
	sprintf_s(hexAddress, "0x%I64x", address);
#else
	sprintf_s(hexAddress, "0x%I32x", address);
#endif
	std::string str{hexAddress};

	return str;
}

std::wstring GenRandStr(const size_t size) // just enough randomness
{
	srand(static_cast<unsigned int>(time(nullptr)));
	static const TCHAR ALPHABET[] =
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		L"abcdefghijklmnopqrstuvwxyz";
	std::wstring randString(size, '\x0');
	for (auto& i : randString)
	{
		i = ALPHABET[rand() / (RAND_MAX / (_tcslen(ALPHABET) - 1) + 1)];
	}

	return randString;
}

TCHAR* NormalizeRegPath(const LPCTSTR regPath)
{
	const auto pathSize = _tcsclen(regPath);
	const auto normalPath = new TCHAR[pathSize + 1]{};
	for (size_t i = 0; i < pathSize; i++)
	{
		if (regPath[i] == *(L"/")) {
			normalPath[i] = *(L"\\");
		} else {
			normalPath[i] = regPath[i];
}
	}
	return normalPath;
}
