; =============================================================================================================================================================

/*
	Master Password (written in AutoHotkey)
	Author ....: jNizM
	Released ..: 2022-10-08
	Modified ..: 2023-03-31
	License ...: MIT
	GitHub ....: https://github.com/jNizM/master-password
	Forum .....: 
*/


; COMPILER DIRECTIVES =========================================================================================================================================

;@Ahk2Exe-SetDescription    MasterPassword (x64)
;@Ahk2Exe-SetFileVersion    0.0.1
;@Ahk2Exe-SetProductName    MasterPassword
;@Ahk2Exe-SetProductVersion 2.0
;@Ahk2Exe-SetCopyright      (c) 2022-2023 jNizM
;@Ahk2Exe-SetLanguage       0x0407


; SCRIPT DIRECTIVES ===========================================================================================================================================

#Requires AutoHotkey v2.0-


; RUN =========================================================================================================================================================


MasterPassword()


; MasterPassword ==============================================================================================================================================

MasterPassword(Secret := "seed.txt")
{
	App := Map("name", "Master Password", "version", "0.0.1", "release", "2023-03-31", "author", "jNizM", "licence", "MIT")


	; GET ACCOUNTS ============================================================================================================================================

	LB_List := Array(), List_Unsorted := ""
	if (FileExist("accounts.txt"))
	{
		try
			File := FileOpen("accounts.txt", "rw", "UTF-8-RAW")
		catch as Err
			MsgBox "Can't open 'accounts.txt'`n`n" Type(Err) ": " Err.Message
		while !(File.AtEOF)
		{
			List_Unsorted .= File.ReadLine() "|"
		}
		File.Close()
		LB_List := StrSplit(Sort(SubStr(List_Unsorted, 1, -1), "D|"), "|")
	}


	; TRAY ====================================================================================================================================================

	if (VerCompare(A_OSVersion, "10.0.22000") >= 0)
		TraySetIcon("shell32.dll", 48)


	; GUI =====================================================================================================================================================

	Main := Gui(, App["name"])
	Main.MarginX := 0
	Main.MarginY := 0
	Main.SetFont("s10 w400", "Segoe UI")

	Main.AddText("xm+15 ym+15 w330 h23 0x200", "Name or Email address")
	ED1 := Main.AddEdit("xm+15 y+2 w305")
	EM_SETCUEBANNER(ED1, "eg. John Doe", True)
	Main.AddCheckbox("x+7 yp h23 Checked").OnEvent("Click", ShowHidePassword)

	Main.AddText("xm+15 y+17 w330 h23 0x200", "Your unique Master Password (Secret)")
	ED2 := Main.AddEdit("xm+15 y+2 w305 +Password")
	EM_SETCUEBANNER(ED2, "eg. autohotkey useful tool", True)
	Main.AddCheckbox("x+7 yp h23").OnEvent("Click", ShowHidePassword)

	Main.AddText("xm+15 y+22 w330 h23 0x200", "Account(s):")
	ED3 := Main.AddEdit("xm+15 y+2 w305")
	ED3.OnEvent("Change", CheckAccounts)
	BT3 := Main.AddButton("x+4 yp h23 w23 +Disabled", Chr(10133))
	BT3.OnEvent("Click", AddRemoveItem)
	LB1 := Main.AddListBox("xm+16 y+5 w330 r8", LB_List)
	LB1.OnEvent("DoubleClick", FocusItem)

	Main.AddText("xm+15 y+12 w330 h23 0x200", "Site Counter")
	ED4 := Main.AddEdit("xm+15 y+2 w330 Number", 1)

	Main.AddText("xm+15 y+12 w162 h23 0x200", "Type")
	Main.AddText("x+6 yp w162 h23 0x200", "Length")
	DL1 := Main.AddDropDownList("xm+15 y+2 w162 Choose1", ["Strong", "Medium", "PIN"])
	DL1.OnEvent("Change", ChangePasswordType)
	ED5 := Main.AddEdit("x+6 yp w162 Number")
	Main.AddUpDown("Range4-64", 32)

	Main.AddButton("xm+14 y+12 w332", "Show Password").OnEvent("Click", GeneratePassword)
	ED6 := Main.AddEdit("xm+15 y+2 w330 +ReadOnly")

	Main.AddButton("xm+14 y+12 w164", "Copy").OnEvent("Click", Event_Copy)
	Main.AddButton("x+4 yp w164", "Copy Temporary").OnEvent("Click", Event_Copy)
	PIC1 := Main.AddPicture("xm y+10 w360 h5 0x4E")

	Main.OnEvent("Close", (*) => (A_Clipboard := "") && ExitApp)
	Main.Show("AutoSize")


	; WINDOW EVENTS ===========================================================================================================================================

	ShowHidePassword(GuiCtrlObj, *)
	{
		switch GuiCtrlObj.ClassNN
		{
			case "Button1":
			{
				switch GuiCtrlObj.Value
				{
					case 0:
						ED1.Opt("+Password")
					case 1:
						ED1.Opt("-Password")
				}
			}
			case "Button2":
			{
				switch GuiCtrlObj.Value
				{
					case 0:
						ED2.Opt("+Password")
					case 1:
						ED2.Opt("-Password")
				}
			}
		}
	}


	Event_Copy(GuiCtrlObj, *)
	{
		switch GuiCtrlObj.Text
		{
			case "Copy":
			{
				global StopLoop := True
				PIC1.Move(,, 360)
				CreateGradient(PIC1.Hwnd, ["0x5CB85C"]*)
			}
			case "Copy Temporary":
			{
				global StopLoop := False
				loop 30
				{
					if (StopLoop)
						break
					PIC1.Move(,, 360 - ((A_Index) * (360 / 30)))
					CreateGradient(PIC1.Hwnd, ["0x5CB85C"]*)
					Sleep 1000
				}
				A_Clipboard := ""
			}
		}
	}


	CheckAccounts(GuiCtrlObj, *)
	{
		ControlSetText Chr(10133), BT3.Hwnd
		if (StrLen(GuiCtrlObj.Value) > 0)
		{
			BT3.Opt("-Disabled")
			LV_List := ControlGetItems(LB1.Hwnd)
			loop LV_List.Length
			{
				if (LV_List[A_Index] = GuiCtrlObj.Value)
				{
					ControlSetText Chr(10134), BT3.Hwnd
				}
			}
		}
		else
		{
			BT3.Opt("+Disabled")
		}
	}


	AddRemoveItem(GuiCtrlObj, *)
	{
		switch GuiCtrlObj.Text
		{
			case Chr(10133):
				AddItem(ED3.Text)
			case Chr(10134):
				RemoveItem(LB1.Value)
		}
	}


	FocusItem(GuiCtrlObj, *)
	{
		ED3.Text := GuiCtrlObj.Text
		ControlSetText Chr(10134), BT3.Hwnd
		BT3.Opt("-Disabled")
	}


	AddItem(NewItem)
	{
		LB1.Opt("-Redraw")
		List_Unsorted := NewItem "|"
		if (FileExist("accounts.txt"))
		{
			try
				File := FileOpen("accounts.txt", "rw", "UTF-8-RAW")
			catch as Err
				MsgBox "Can't open 'accounts.txt'`n`n" Type(Err) ": " Err.Message
			while !(File.AtEOF)
			{
				List_Unsorted .= File.ReadLine() "|"
			}
			File.Close()
			FileDelete "accounts.txt"
		}
		LB_List := StrSplit(Sort(SubStr(List_Unsorted, 1, -1), "D|"), "|")
		loop LB_List.Length
		{
			FileAppend LB_List[A_Index] (LB_List.Length = A_Index ? "" : "`n"), "accounts.txt"
		}
		LB1.Delete()
		LB1.Add(LB_List)
		LB1.Opt("+Redraw")
		CheckAccounts(ED3)
	}


	RemoveItem(OldItem)
	{
		LB1.Opt("-Redraw")
		LB1.Delete(OldItem)
		LB_List := ControlGetItems(LB1.Hwnd)
		FileDelete "accounts.txt"
		loop LB_List.Length
		{
			FileAppend LB_List[A_Index] (LB_List.Length = A_Index ? "" : "`n"), "accounts.txt"
		}
		LB1.Opt("+Redraw")
		CheckAccounts(ED3)
	}


	ChangePasswordType(GuiCtrlObj, *)
	{
		switch GuiCtrlObj.Value
		{
			case 1:
				ED5.Text := 32
			case 2:
				ED5.Text := 20
			case 3:
				ED5.Text :=  4
		}
	}


	GeneratePassword(*)
	{
		local master_key
		local master_seed
		master_seed := ""
		if (FileExist(Secret))
		{
			try
				File := FileOpen(Secret, "r")
			catch as Err
				MsgBox "Can't open '" Secret "'`n`n" Type(Err) ": " Err.Message
			master_seed := File.Read()
			File.Close()
		}
		master_key  := Hash.PBKDF2("SHA512", ED1.Text, ED2.Text . (master_seed ? master_seed : ""), 32768, 512)
		site_key    := Hash.HMAC("SHA512", ED3.Text . ED4.Text, master_key)
		master_key  := ""
		master_seed := ""
		switch DL1.Value
		{
			case 1:
				ED6.Text := SubStr(Ascii85(site_key), 1, ED5.Text)
			case 2:
				ED6.Text := SubStr(Base64(site_key), 1, ED5.Text)
			case 3:
				ED6.Text := SubStr(Base10(site_key), 1, ED5.Text)
		}
	}


	Base10(Input)
	{
		static _MAX_U64TOSTR_BASE2_COUNT := (64 + 1)

		Data := StrSplit(Input)
		loop Data.length // 2
		{
			Value := DllCall("msvcrt\_wcstoui64", "Str", (Data[A_Index] . Data[A_Index + 1]), "Ptr", 0, "Int", 16, "cdecl Int64")
			VarSetStrCapacity(&Encoded, _MAX_U64TOSTR_BASE2_COUNT)
			DllCall("msvcrt\_i64tow", "Int64", Value, "Str", Encoded, "Int", 10, "cdecl Str")
			Output .= Encoded
		}
		return Output
	}


	Base64(Input, Encoding := "UTF-8")
	{
		static CRYPT_STRING_BASE64 := 0x00000001
		static CRYPT_STRING_NOCRLF := 0x40000000

		Binary := Buffer(StrPut(Input, Encoding))
		StrPut(Input, Binary, Encoding)
		if !(DllCall("crypt32\CryptBinaryToStringW", "Ptr", Binary, "UInt", Binary.Size - 1, "UInt", (CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF), "Ptr", 0, "UInt*", &Size := 0))
			throw OSError()

		Output := Buffer(Size << 1, 0)
		if !(DllCall("crypt32\CryptBinaryToStringW", "Ptr", Binary, "UInt", Binary.Size - 1, "UInt", (CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF), "Ptr", Output, "UInt*", Size))
			throw OSError()

		return StrGet(Output)
	}


	Ascii85(Input)
	{
		Data := StrSplit(Input)

		if (Mod(Data.Length, 4))
			return false

		Value := 0, Output := ""
		loop Data.Length
		{
			Value := Value * 256 + Ord(Data[A_Index])
			if !(Mod(A_Index, 4))
			{
				loop 5
					Output .= Chr(33 + Mod(Value // 85 ** (5 - A_Index), 85))
				Value := 0
			}
		}
		return Output
	}


	; Messages ================================================================================================================================================

	EM_SETCUEBANNER(handle, string, option := false)
	{
		static ECM_FIRST       := 0x1500
		static EM_SETCUEBANNER := ECM_FIRST + 1

		SendMessage(EM_SETCUEBANNER, option, StrPtr(string), handle)
	}


	; Functions ===============================================================================================================================================

	CreateGradient(Handle, Colors*)
	{
		static IMAGE_BITMAP        := 0
		static LR_COPYDELETEORG    := 0x00000008
		static LR_CREATEDIBSECTION := 0x00002000
		static STM_SETIMAGE        := 0x0172
		global hBITMAP

		ControlGetPos(,, &OutW, &OutW, Handle)
		Addr := Bits := Buffer(Colors.Length * 2 * 4)
		for each, Color in Colors
			Addr := NumPut("UInt", Color, "UInt", Color, Addr)

		hBITMAP := DllCall("gdi32\CreateBitmap", "Int", 2, "Int", Colors.Length, "UInt", 1, "UInt", 32, "Ptr", 0, "Ptr")
		hBITMAP := DllCall("user32\CopyImage", "Ptr", hBITMAP, "UInt", IMAGE_BITMAP, "Int", 0, "Int", 0, "UInt", LR_COPYDELETEORG | LR_CREATEDIBSECTION, "Ptr")
		DllCall("gdi32\SetBitmapBits", "Ptr", hBITMAP, "UInt", Bits.Size, "Ptr", Bits)
		hBITMAP := DllCall("user32\CopyImage", "Ptr", hBITMAP, "UInt", 0, "Int", OutW, "Int", OutW, "UInt", LR_COPYDELETEORG | LR_CREATEDIBSECTION, "Ptr")
		SendMessage(STM_SETIMAGE, IMAGE_BITMAP, hBitMAP, Handle)
		return true
	}
}



; INCLUDES ====================================================================================================================================================

; #Include Class_CNG.ahk

/*
	AutoHotkey wrapper for CNG (Cryptography API: Next Generation)

	Author ....: jNizM
	Released ..: 2016-09-16
	Modified ..: 2021-11-03
	License ...: MIT
	GitHub ....: https://github.com/jNizM/AHK_CNG
	Forum .....: https://www.autohotkey.com/boards/viewtopic.php?t=96117
*/

; SCRIPT DIRECTIVES ===========================================================================================================================================


class Hash extends CNG
{
	static HMAC(AlgId, String, Hmac, Encoding := "UTF-8", Output := "HEXRAW")
	{
		static hAlgorithm := 0, hHash := 0

		try
		{
			; verify the hash algorithm identifier
			if !(ALGORITHM := this.BCrypt.HashAlgorithm(AlgId))
				throw Error("Unrecognized hash algorithm identifier: " AlgId, -1)

			; open an algorithm handle
			hAlgorithm := this.BCrypt.OpenAlgorithmProvider(ALGORITHM, this.BCrypt.Constants.BCRYPT_ALG_HANDLE_HMAC_FLAG)

			; create a hash
			Mac := this.StrBuf(Hmac, Encoding)
			hHash := this.BCrypt.CreateHash(hAlgorithm, Mac, Mac.Size - 1)

			; hash some data
			Data := this.StrBuf(String, Encoding)
			this.BCrypt.HashData(hHash, Data, Data.Size - 1)

			; calculate the length of the hash
			HASH_LENGTH := this.BCrypt.GetProperty(hAlgorithm, this.BCrypt.Constants.BCRYPT_HASH_LENGTH, 4)

			; close the hash
			HASH_DATA := Buffer(HASH_LENGTH, 0)
			FINISH_HASH := this.BCrypt.FinishHash(hHash, &HASH_DATA, HASH_LENGTH)

			; convert bin to string (base64 / hex)
			HASH := this.Crypt.BinaryToString(HASH_DATA, HASH_LENGTH, Output)
		}
		catch as Exception
		{
			; represents errors that occur during application execution
			throw Exception
		}
		finally
		{
			; cleaning up resources
			if (hHash)
				this.BCrypt.DestroyHash(hHash)

			if (hAlgorithm)
				this.BCrypt.CloseAlgorithmProvider(hAlgorithm)
		}

		return HASH
	}



	static PBKDF2(AlgId, Password, Salt, Iterations := 4096, KeySize := 256, Encoding := "UTF-8", Output := "HEXRAW")
	{
		static hAlgorithm := 0, hHash := 0

		try
		{
			; verify the hash algorithm identifier
			if !(ALGORITHM := this.BCrypt.HashAlgorithm(AlgId))
				throw Error("Unrecognized hash algorithm identifier: " AlgId, -1)

			; check key bit length
			if (Mod(KeySize, 8) != 0)
				throw Error("The desired key bit length must be a multiple of 8!", -1)

			; open an algorithm handle
			hAlgorithm := this.BCrypt.OpenAlgorithmProvider(ALGORITHM, this.BCrypt.Constants.BCRYPT_ALG_HANDLE_HMAC_FLAG)

			; derives a key from a hash value
			PBKDF2_DATA := this.BCrypt.DeriveKeyPBKDF2(hAlgorithm, Password, Salt, Iterations, KeySize / 8, Encoding)

			; convert bin to string (base64 / hex)
			PBKDF2 := this.Crypt.BinaryToString(PBKDF2_DATA, PBKDF2_DATA.size, Output)
		}
		catch as Exception
		{
			; represents errors that occur during application execution
			throw Exception
		}
		finally
		{
			; cleaning up resources
			if (hAlgorithm)
				this.BCrypt.CloseAlgorithmProvider(hAlgorithm)
		}

		return PBKDF2
	}
}


; =============================================================================================================================================================


class CNG
{

	class BCrypt
	{

		#DllLoad "*i bcrypt.dll"


		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.CloseAlgorithmProvider
		; //
		; // This function closes an algorithm provider.
		; //
		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static CloseAlgorithmProvider(hAlgorithm)
		{
			NT_STATUS := DllCall("bcrypt\BCryptCloseAlgorithmProvider", "Ptr",  hAlgorithm
			                                                          , "UInt", Flags := 0
			                                                          , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return true
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.CreateHash
		; //
		; // This function is called to create a hash or Message Authentication Code (MAC) object.
		; //
		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static CreateHash(hAlgorithm, Buf := 0, Size := 0)
		{
			NT_STATUS := DllCall("bcrypt\BCryptCreateHash", "Ptr",  hAlgorithm
			                                              , "Ptr*", &hHash := 0
			                                              , "Ptr",  0
			                                              , "UInt", 0
			                                              , "Ptr",  Buf
			                                              , "UInt", Size
			                                              , "UInt", Flags := 0
			                                              , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return hHash
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.DeriveKeyPBKDF2
		; //
		; // This function derives a key from a hash value by using the PBKDF2 key derivation algorithm as defined by RFC 2898.
		; //
		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static DeriveKeyPBKDF2(hAlgorithm, Pass, Salt, Iterations, DerivedKey, Encoding := "UTF-8")
		{
			Passwd := CNG.StrBuf(Pass, Encoding)
			Salt   := CNG.StrBuf(Salt, Encoding)
			DKey   := Buffer(DerivedKey, 0)

			NT_STATUS := DllCall("bcrypt\BCryptDeriveKeyPBKDF2", "Ptr",   hAlgorithm
			                                                   , "Ptr",   Passwd
			                                                   , "UInt",  Passwd.Size - 1
			                                                   , "Ptr",   Salt
			                                                   , "UInt",  Salt.Size - 1
			                                                   , "Int64", Iterations
			                                                   , "Ptr",   DKey
			                                                   , "UInt",  DerivedKey
			                                                   , "UInt",  Flags := 0
			                                                   , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return DKey
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.DestroyHash
		; //
		; // This function destroys a hash or Message Authentication Code (MAC) object.
		; //
		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static DestroyHash(hHash)
		{
			NT_STATUS := DllCall("bcrypt\BCryptDestroyHash", "Ptr", hHash, "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return true
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.FinishHash
		; //
		; // This function retrieves the hash or Message Authentication Code (MAC) value for the data accumulated from prior calls to BCrypt.HashData.
		; //
		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static FinishHash(hHash, &Buf, Size)
		{
			Buf := Buffer(Size, 0)
			NT_STATUS := DllCall("bcrypt\BCryptFinishHash", "Ptr",  hHash
			                                              , "Ptr",  Buf
			                                              , "UInt", Size
			                                              , "UInt", Flags := 0
			                                              , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return Size
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.GetProperty
		; //
		; // This function retrieves the value of a named property for a CNG object.
		; //
		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static GetProperty(hObject, Property, Size)
		{
			NT_STATUS := DllCall("bcrypt\BCryptGetProperty", "Ptr",   hObject
			                                               , "Ptr",   StrPtr(Property)
			                                               , "Ptr*",  &Buf := 0
			                                               , "UInt",  Size
			                                               , "UInt*", &Result := 0
			                                               , "UInt",  Flags := 0
			                                               , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return Buf
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.HashData
		; //
		; // This function performs a one way hash or Message Authentication Code (MAC) on a data buffer.
		; //
		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static HashData(hHash, Buf, Size)
		{
			NT_STATUS := DllCall("bcrypt\BCryptHashData", "Ptr",  hHash
			                                            , "Ptr",  Buf
			                                            , "UInt", Size
			                                            , "UInt", Flags := 0
			                                            , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return true
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: BCrypt.OpenAlgorithmProvider
		; //
		; // This function loads and initializes a CNG provider.
		; //
		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static OpenAlgorithmProvider(AlgId, Flags := 0)
		{
			NT_STATUS := DllCall("bcrypt\BCryptOpenAlgorithmProvider", "Ptr*", &hAlgorithm := 0
			                                                         , "Str",  AlgId
			                                                         , "Ptr",  Implementation := 0
			                                                         , "UInt", Flags
			                                                         , "UInt")

			if (NT_STATUS = this.NT.SUCCESS)
				return hAlgorithm
			throw Error(this.GetErrorMessage(NT_STATUS), -1)
		}


		static GetErrorMessage(STATUS_CODE)
		{
			switch STATUS_CODE
			{
				case this.NT.AUTH_TAG_MISMATCH:
					return "The computed authentication tag did not match the input authentication tag."
				case this.NT.BUFFER_TOO_SMALL:
					return "The buffer is too small to contain the entry. No information has been written to the buffer."
				case this.NT.INVALID_BUFFER_SIZE:
					return "The size of the buffer is invalid for the specified operation."
				case this.NT.INVALID_HANDLE:
					return "An invalid HANDLE was specified."
				case this.NT.INVALID_PARAMETER:
					return "An invalid parameter was passed to a service or function."
				case this.NT.NOT_FOUND:
					return "The object was not found."
				case this.NT.NOT_SUPPORTED:
					return "The request is not supported."
				case this.NT.NO_MEMORY:
					return "Not enough virtual memory or paging file quota is available to complete the specified operation."
				default:
					return "BCrypt failed " STATUS_CODE
			}
		}


		class Constants
		{
			static BCRYPT_ALG_HANDLE_HMAC_FLAG            := 0x00000008

			; https://docs.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
			static BCRYPT_MD2_ALGORITHM                   := "MD2"
			static BCRYPT_MD4_ALGORITHM                   := "MD4"
			static BCRYPT_MD5_ALGORITHM                   := "MD5"
			static BCRYPT_SHA1_ALGORITHM                  := "SHA1"
			static BCRYPT_SHA256_ALGORITHM                := "SHA256"
			static BCRYPT_SHA384_ALGORITHM                := "SHA384"
			static BCRYPT_SHA512_ALGORITHM                := "SHA512"
			static BCRYPT_PBKDF2_ALGORITHM                := "PBKDF2"

			; https://docs.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers
			static BCRYPT_CHAINING_MODE                   := "ChainingMode"
			static BCRYPT_HASH_LENGTH                     := "HashDigestLength"
		}


		class NT
		{
			static SUCCESS             := 0x00000000
			static AUTH_TAG_MISMATCH   := 0xC000A002
			static BUFFER_TOO_SMALL    := 0xC0000023
			static INVALID_BUFFER_SIZE := 0xC0000206
			static INVALID_HANDLE      := 0xC0000008
			static INVALID_PARAMETER   := 0xC000000D
			static NO_MEMORY           := 0xC0000017
			static NOT_FOUND           := 0xC0000225
			static NOT_SUPPORTED       := 0xC00000BB
		}

		static HashAlgorithm(Algorithm)
		{
			switch Algorithm
			{
				case "MD2":               return this.Constants.BCRYPT_MD2_ALGORITHM
				case "MD4":               return this.Constants.BCRYPT_MD4_ALGORITHM
				case "MD5":               return this.Constants.BCRYPT_MD5_ALGORITHM
				case "SHA1", "SHA-1":     return this.Constants.BCRYPT_SHA1_ALGORITHM
				case "SHA256", "SHA-256": return this.Constants.BCRYPT_SHA256_ALGORITHM
				case "SHA384", "SHA-384": return this.Constants.BCRYPT_SHA384_ALGORITHM
				case "SHA512", "SHA-512": return this.Constants.BCRYPT_SHA512_ALGORITHM
				default: return ""
			}
		}
	}


	; =========================================================================================================================================================


	class Crypt
	{

		#DllLoad "*i crypt32.dll"


		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: Crypt.BinaryToString
		; //
		; // This function converts an array of bytes into a formatted string.
		; //
		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static BinaryToString(BufIn, SizeIn, Flags := "BASE64")
		{
			static CRYPT_STRING :=  { BASE64: 0x1, BINARY: 0x2, HEX: 0x4, HEXRAW: 0xc }
			static CRYPT_STRING_NOCRLF := 0x40000000

			if !(DllCall("crypt32\CryptBinaryToStringW", "Ptr",   BufIn
			                                           , "UInt",  SizeIn
			                                           , "UInt",  (CRYPT_STRING.%Flags% | CRYPT_STRING_NOCRLF)
			                                           , "Ptr",   0
			                                           , "UInt*", &Size := 0))
				throw Error("Can't compute the destination buffer size, error: " A_LastError, -1)

			BufOut := Buffer(Size << 1, 0)
			if !(DllCall("crypt32\CryptBinaryToStringW", "Ptr",   BufIn
			                                           , "UInt",  SizeIn
			                                           , "UInt",  (CRYPT_STRING.%Flags% | CRYPT_STRING_NOCRLF)
			                                           , "Ptr",   BufOut
			                                           , "UInt*", Size))
				throw Error("Can't convert source buffer to " Flags ", error: " A_LastError, -1)

			return StrGet(BufOut)
		}


		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		; //
		; // FUNCTION NAME: Crypt.StringToBinary
		; //
		; // This function converts a formatted string into an array of bytes.
		; //
		; /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		static StringToBinary(String, &Binary, Flags := "BASE64")
		{
			static CRYPT_STRING := { BASE64: 0x1, BINARY: 0x2, HEX: 0x4, HEXRAW: 0xc }

			if !(DllCall("crypt32\CryptStringToBinaryW", "Ptr",   StrPtr(String)
			                                           , "UInt",  0
			                                           , "UInt",  CRYPT_STRING.%Flags%
			                                           , "Ptr",   0
			                                           , "UInt*", &Size := 0
			                                           , "Ptr",   0
			                                           , "Ptr",   0))
				throw Error("Can't compute the destination buffer size, error: " A_LastError, -1)

			Binary := Buffer(Size, 0)
			if !(DllCall("crypt32\CryptStringToBinaryW", "Ptr",   StrPtr(String)
			                                           , "UInt",  0
			                                           , "UInt",  CRYPT_STRING.%Flags%
			                                           , "Ptr",   Binary
			                                           , "UInt*", Binary.Size
			                                           , "Ptr",   0
			                                           , "Ptr",   0))
				throw Error("Can't convert source buffer to " Flags ", error: " A_LastError, -1)

			return Binary.Size
		}
	}


	; =========================================================================================================================================================


	static StrBuf(Str, Encoding := "UTF-8")
	{
		Buf := Buffer(StrPut(Str, Encoding))
		StrPut(Str, Buf, Encoding)
		return Buf
	}

}

; =============================================================================================================================================================
