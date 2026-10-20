#pragma once

#include <string>

namespace WinSys {
	enum class SignatureStatus {
		Valid,		// signed and trusted
		NotSigned,	// no embedded signature and no catalog
		Invalid,	// signed, but the signature or the chain doesn't verify (Error)
		Error,		// the file couldn't be read (Error)
	};

	struct SignatureInfo {
		SignatureStatus Status{ SignatureStatus::Error };
		bool Catalog{ false };	// verified through a catalog
		std::wstring Signer;	// the signing certificate's subject
		DWORD Error{ 0 };		// the trust or file error, for Invalid and Error
	};

	//
	// Authenticode verification of a file: its embedded signature, or, if it has none, a system catalog that lists its
	// hash (most Windows binaries are catalog signed). No revocation checks, so nothing goes to the network. Safe on any
	// thread; the catalog lookups may use COM, so a thread of its own should initialize it.
	//
	struct FileSignature final {
		[[nodiscard]] static SignatureInfo Verify(PCWSTR path);
	};
}
