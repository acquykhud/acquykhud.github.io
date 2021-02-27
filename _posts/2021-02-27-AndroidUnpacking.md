---
path: ""
type: posts
values:
layout: article
sharing: true
license: false
aside:
    toc: true
show_edit_on_github: false
show_subscribe: false
pageview: true
title: "[RE] Unpack game android sử dụng custom mono library"
excerpt: 'Unpack game android sử dụng custom mono library'
author: true
---

Mình trước giờ rất ít đụng tới android, nên kiến thức về hệ điều hành này gần như không có. Gần đây có dịp được làm việc với hệ điều hành android nên mới có thêm chút thời gian để nghiên cứu.

Mình chợt nhớ lại hồi lâu, cách đây 1 năm mình có chơi game 1 con game bắn zombie trên android. Game này thì được làm bằng Unity (lúc vào game nó ghi vậy nên mình biết vậy). Lúc đó mình đã thử hack game này. Vì chơi qua một vài CTF nên mình biết, để hack game Unity thì chỉ cần chỉnh sửa file **"Assembly-CSharp.dll"**. Tuy nhiên khi mình extract file đó ra từ file .apk thì thấy file được mã hoá bằng một cách nào đó.

<p align="center">
    <img src="/assets/images/androidunpacking/1.png"/>
    <center><figcaption><b>Hình 1: File Assembly-CSharp.dll bị mã hoá</b></figcaption></center>
</p>


Vì đây là dịp để mình học thêm về android, nên mình quyết định tìm hiểu tại sao file bị mã hoá mà game vẫn chơi được bình thường.

## Công cụ, yêu cầu

Kiến thức cần biết:

- PE header. Có thể tham khảo [tại đây](https://blog.kowalczyk.info/articles/pefileformat.html).
- dotNet header: tham khảo [tại đây](https://www.ntcore.com/files/dotnetformat.htm).

Công cụ sử dụng trong bài: IDA pro, [CFF explorer](https://ntcore.com/?page_id=388) , [HxD](https://mh-nexus.de/en/hxd/), Notepad++, dnSpy, và VSCode.

Game mình RE là [Dead Trigger 2](https://play.google.com/store/apps/details?id=com.madfingergames.deadtrigger2&hl=en&gl=US) bản 1.6.7. Vì đây là bản mà hồi đó mình chơi (mình nhớ mang máng). Bạn đọc có thể tải file APK ở các trang như apkmirror, ...

Giờ ta có thể bắt đầu vào phần chính rồi.

## Stage 1: Decrypt Assembly-CSharp.dll

Thông thường, nếu file **Assembly-CSharp.dll** không bị mã hoá, ta có thể dùng dnSpy hoặc ILSpy để có thể decompile nó, ngoài ra có thể chỉnh sửa nó để hack game theo ý muốn. Nhưng mình thắc mắc, android là hệ điều hành nhân linux, làm sao có thể load được file PE. Vì vậy mình đã google câu hỏi này, và tìm được câu trả lời ở trang stackoverflow

> [https://stackoverflow.com/questions/49955202/how-does-an-apk-file-include-dll-files-can-android-run-dll-files](https://stackoverflow.com/questions/49955202/how-does-an-apk-file-include-dll-files-can-android-run-dll-files)

Câu trả lời là, Unity sử dụng thư viện [mono](https://github.com/mono/mono) để load file dll. Đây là một thư viện mã nguồn mở nên chúng ta sẽ dùng nó để tham khảo. Mình google để tìm xem thư viện này hoạt động như nào:

> [https://www.cnblogs.com/eniac1946/p/7485173.html](https://www.cnblogs.com/eniac1946/p/7485173.html)

Bài trên viết bằng tiếng Trung Quốc, mình translate sang tiếng Anh để đọc. Ở trong bài đó có workflow của mono như sau:

<p align="center">
    <img src="/assets/images/androidunpacking/2.png"/>
    <center><figcaption><b>Hình 2: Luồng hoạt động của mono</b></figcaption></center>
</p>


Như hình trên thì hàm `do_mono_load_image` sẽ được thực hiện, nghe tên có vẻ như hàm này sẽ dùng để load file.

Hàm này nằm trong file `libmono.so` chứa trong file apk. Để lấy được file này, ta đổi tên file .apk này thành .zip, giải nén ra thì file `libmono.so` sẽ nằm ở: `dead_trigger_2_v1.6.7\lib\x86\libmono.so`, còn file `Assembly-CSharp.dll` nằm ở `"\dead_trigger_2_v1.6.7\assets\bin\Data\Managed\Assembly-CSharp.dll"`.

Tiếp theo ta mở file `libmono.so` bằng IDA pro lên, còn source code mono, ta clone về rồi mở lên bằng VSCode.

Trong source code:

```c++
static MonoImage *
do_mono_image_load (MonoImage *image, MonoImageOpenStatus *status,
		    gboolean care_about_cli, gboolean care_about_pecoff)
{
	ERROR_DECL (error);
	GSList *l;
	MONO_PROFILER_RAISE (image_loading, (image));
	mono_image_init (image);
   // ...
    
	if (care_about_cli == FALSE) {
		goto done;
	}
	if (image->loader == &pe_loader && !image->metadata_only && !mono_verifier_verify_cli_data (image, error))
		goto invalid_image;
	if (!mono_image_load_cli_data (image))
		goto invalid_image;
   // ...
	if (image->loader == &pe_loader && !image->metadata_only && !mono_verifier_verify_table_data (image, error))
		goto invalid_image;
	// ...
	mono_image_close (image);
	return NULL;
}
```

Trong IDA:

```c++
MonoImage *__cdecl sub_1A24B3(MonoImage *a1, _DWORD *a2, int care_about_cli, int care_about_pecoff)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v7[7] = '\x8F';
  qmemcpy(v7, "\x1F\b-\vfs1", 7);
  v6 = 1;
  v5 = 0xD0;
  sub_1A240A(a1->raw_data, a1->raw_data_len, &v7[4], v7, &v6, &v5);// <---------------- ??????????????
  for ( i = 0; i <= 99; ++i )
    ;
  mono_profiler_module_event(a1, 0);
  HIBYTE(a1->_bf_10) = (4 * (sub_21A30E(a1) & 1)) | HIBYTE(a1->_bf_10) & 0xFB;
  mono_image_init(a1);
  v9 = a1->image_info;
  v8 = v9;
  if ( a2 )
    *a2 = 3;                                    // MONO_IMAGE_IMAGE_INVALID
  if ( !care_about_pecoff )
    goto DONE;
  if ( !mono_image_load_pe_data(a1) )
    goto LABEL_16;
  if ( care_about_cli )
  {
    if ( mono_image_load_cli_data(a1) && verify_tables_data_wrapper(a1, 0) && (v9->cli_cli_header.ch_flags & 1) != 0 )
    {
      check_2(a1);
      check_3(a1);
      goto DONE;
    }
LABEL_16:
    mono_profiler_module_loaded(a1, 1);
    mono_image_close(a1);
    return 0;
  }
DONE:
  mono_profiler_module_loaded(a1, 0);
  if ( a2 )
    *a2 = 0;
  return a1;
}
```

Đầu tiên, mình khẳng định hai hàm trên chính là `do_mono_image_load`, nhưng source code trông khác nhau vì phiên bản. Có thể game dùng phiên bản mono cũ hơn mà mình cũng không biết nó là bản nào.

Source code decompile bằng IDA không còn debug symbol, mình đã xem các hàm, so sánh với source code gốc, thêm vào các struct và rename lại như trên. Trong đoạn code trên có lời gọi hàm `sub_1A240A` mà trong source code gốc không có. Mình thử xem hàm này có gì

```c++
int __cdecl sub_1A240A(BYTE *data, int len, BYTE *key1, BYTE *key2, _BYTE *init_1, _BYTE *init_2)
{
  // ... init
  for ( i = 0; ; i += 4 )
  {
    result = i;
    if ( i >= len - len % 4 )
      break;
    data[i + 3] = *init_1 ^ (i + data[i + 3] - *init_2);
    f1A23A5_decrypt(data, i, key2, key1); // call function below
  }
  return result;
}

BYTE *__cdecl f1A23A5_decrypt(BYTE *a1, int offset, BYTE *key1, BYTE *key2)
{
	// ... init
  result = &a1[offset];
  v6 = &a1[offset];
  for ( i = 0; i <= 3; ++i )
  {
    v5 = key2[i] ^ (offset + v6[i] - key1[i]);
    result = v5;
    v6[i] = v5;
  }
  return result;
}
```

Rõ ràng hàm `sub_1A240A` dùng để decrypt file **Assembly-CSharp.dll**, mình viết lại 2 hàm này rồi decypt file, thì được file mới. Mở file này lên bằng HxD, hi vọng sẽ được file PE:

<p align="center">
    <img src="/assets/images/androidunpacking/3.png"/>
    <center><figcaption><b>Hình 3: File Assembly-CSharp.dll sau khi decrypt</b></figcaption></center>
</p>


File mới không phải là file PE vì không bắt đầu bằng 2 byte "MZ". Tuy nhiên nếu bạn đọc để ý kỹ sẽ thấy file trên rất giống file PE, ta có thể thấy một số string như ".text", ".reloc", ".rsrc", ... đó chính là tên các section ta thường thấy ở các file PE. 

## Stage 2: Khôi phục lại file PE

Tiếp theo, mono gọi hàm `pe_image_load_pe_data`:

Source code:

```c++
static gboolean
pe_image_load_pe_data (MonoImage *image)
{
	// init
	iinfo = image->image_info;
	header = &iinfo->cli_header;
	if (offset + sizeof (msdos) > image->raw_data_len)
		goto invalid_image;

	memcpy (&msdos, image->raw_data + offset, sizeof (msdos));
	
	if (!(msdos.msdos_sig [0] == 'M' && msdos.msdos_sig [1] == 'Z'))
		goto invalid_image;
	msdos.pe_offset = GUINT32_FROM_LE (msdos.pe_offset);
	offset = msdos.pe_offset;
	offset = do_load_header (image, header, offset);
    // ...
}
```

Trong IDA:

```c++
_BOOL4 __cdecl pe_image_load_pe_data(MonoImage *a1)
{
	//...
  v2 = a1->image_info;
  v3 = do_load_header(a1, v2, 0);
  return v3 >= 0 && load_section_tables(a1, v2, v3);
}
```

Ta thấy ngay phần check "MZ" đã bị loại bỏ. Vậy là file mà ta decrypt được là file PE nhưng bị xoá đi một vài thành phần của dos header. Giờ ta check xem hàm `do_load_header` làm gì

Source code:

```c++
static int 
do_load_header_internal (const char *raw_data, guint32 raw_data_len, MonoDotNetHeader *header, int offset, gboolean image_is_module_handle)
{
	// ...
	if (offset + sizeof(MonoDotNetHeader32) > raw_data_len)
		return -1;
	memcpy (header, raw_data + offset, sizeof (MonoDotNetHeader));
	if (header->pesig [0] != 'P' || header->pesig [1] != 'E' || header->pesig [2] || header->pesig [3])
		return -1;
   // ..
   	if (header->pe.pe_magic == 0x10B) {
		offset += sizeof (MonoDotNetHeader);
   // ..
    return offset;
}
```

Trong IDA:

```c++
int __cdecl do_load_header(MonoImage *a1, MonoCLIImageInfo *dest, int a3)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]
  if ( a3 + 134 > a1->raw_data_len )
    return -1;
  memcpy(dest, &a1->raw_data[a3], 134u);
  if ( dest->cli_header.optMagic == 0x10B )
}
```

Ta cũng có thể thấy ngay phần check "PE\0\0" cũng bị loại bỏ. Giờ ta đến với hàm `load_sections_table`:

Source code:

```c++
static int
load_section_tables (MonoImage *image, MonoCLIImageInfo *iinfo, guint32 offset)
{
	const int top = iinfo->cli_header.coff.coff_sections;
	int i;
	iinfo->cli_section_count = top;
	iinfo->cli_section_tables = g_new0 (MonoSectionTable, top);
	iinfo->cli_sections = g_new0 (void *, top);
	for (i = 0; i < top; i++){
		MonoSectionTable *t = &iinfo->cli_section_tables [i];

		if (offset + sizeof (MonoSectionTable) > image->raw_data_len)
			return FALSE;
		memcpy (t, image->raw_data + offset, sizeof (MonoSectionTable));
		offset += sizeof (MonoSectionTable);
	return TRUE;
}
```

IDA:

```c++
int __cdecl sub_1A12C7(int a1, char *a2, int a3)
{
  int v4; // [esp+18h] [ebp-10h]
  int i; // [esp+1Ch] [ebp-Ch]

  v4 = *(unsigned __int16 *)a2;                 // raw data
  *((_DWORD *)a2 + 34) = v4;
  *((_DWORD *)a2 + 35) = call_malloc(40 * v4);
  *((_DWORD *)a2 + 36) = call_malloc(4 * v4);
  for ( i = 0; i < v4; ++i )
  {
    if ( (unsigned int)(a3 + 40) > *(_DWORD *)(a1 + 12) )
      return 0;
    memcpy((void *)(*((_DWORD *)a2 + 35) + 40 * i), (const void *)(*(_DWORD *)(a1 + 8) + a3), 40u);
    a3 += 40;
  }
  return 1;
}
```

Ta có thể so sánh và thấy ngay v4 chính là số section, và nó là 1 word ở ngay đầu file.

<p align="center">
    <img src="/assets/images/androidunpacking/4.png"/>
    <center><figcaption><b>Hình 4: File này gồm 3 section</b></figcaption></center>
</p>


Điều này cũng hợp lý vì ta chỉ thấy tên của 3 section trong phần hexdump là ".text", ".rsrc" và ".reloc". Đến đây ta đã có thể rebuild lại phần header cho file:

```c++
int main()
{
	FILE* f = fopen("C:\\Users\\xikhud\\Desktop\\new.dll", "wb");
	unsigned int size;
	char* data = (char*)readFile("C:\\Users\\xikhud\\Desktop\\Assembly-CSharp-dec.dll", &size);
	IMAGE_DOS_HEADER dos = { 0 };
	dos.e_magic = 0x5A4D;
	dos.e_lfanew = 0x80;
	writeFile(f, &dos, sizeof(dos)); // dos header
	for (int i = 0; i < 0x80 - sizeof(dos); ++i)
	{
		char a = 'A';
		writeFile(f, &a, 1);
	}
	IMAGE_NT_HEADERS32 nt = { 0 };
	nt.Signature = *(DWORD*)"PE\x00\x00";
	nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
	nt.FileHeader.NumberOfSections = 3;
	nt.FileHeader.SizeOfOptionalHeader = 224;
	nt.FileHeader.Characteristics = 0x2022;

	nt.OptionalHeader.Magic = 0x10B;
	nt.OptionalHeader.NumberOfRvaAndSizes = 0x10;

	nt.OptionalHeader.DataDirectory[14].VirtualAddress = 0x2000;
	nt.OptionalHeader.DataDirectory[14].Size = 0x48;

	writeFile(f, &nt, sizeof(nt));

	for (int i = 0; i < nt.FileHeader.NumberOfSections; ++i)
	{
		writeFile(f, data + 134 + i * sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER));
	}
	if (written > 0x200)
		return 1;
	unsigned int pad = 0x200 - written;
	for (int i = 0; i < pad; ++i)
	{
		char a = '\x00';
		writeFile(f, &a, 1);
	}
	MonoCLIHeader netHeader;
	memcpy(&netHeader, data + 0x208, sizeof(netHeader));
	writeFile(f, &netHeader, sizeof(netHeader));
	writeFile(f, data + written, 3740160 - written);
	fclose(f);
	return 0;
}
```

> Với file dotNET, đa số các trường trong phần dos và PE header không quan trọng, nên ta có thể để giá trị tuỳ ý. dnSpy và ILSpy không quan tâm tới các giá trị đó.

Chạy đoạn code trên ta được 1 file mới tên là "new.dll". Ta mở file này lên trong CFF Explorer và bấm ngay vào phần ".NET directory", vì đây là thông tin mà dnSpy cần để decompile file dotNet.

<p align="center">
    <img src="/assets/images/androidunpacking/5.png"/>
    <center><figcaption><b>Hình 5: Phần .NET directory</b></figcaption></center>
</p>


Ta có thể thấy ngay là phần **Metadata RVA** bị sai ngay, ngoài ra phần **Metadata Size** cũng vậy. Đó là một con số vô lý, nó lớn hơn tất cả phần **VirtualAddress** ở tất cả các section. Tiếp tục RE, mình thấy hàm `load_metadata_ptrs` như sau:

Source code:

```c++
offset = mono_cli_rva_image_map (image, iinfo->cli_cli_header.ch_metadata.rva);
```

IDA (hàm này là sub_1A1491):

```c++
*(_DWORD *)(a1 + 52) = mono_cli_rva_image_map(a1, *(_DWORD *)(a2 + 156) ^ 0xE9B03A28) + *(_DWORD *)(a1 + 8);
```

Con số RVA đó đã được xor với 0xE9B03A28. Ta có 0xE9AAD7F0 ^ 0xE9B03A28 = 0x1AEDD8. Vậy RVA chính là 0x1AEDD8, ta sửa con số này vào phần **Metadata RVA** trong CFF Explorer.

Sau khi sửa xong, ta có thể đến phần **Metadata Header** trong CFF Explorer để xem. Ngoài ra ta mở thêm 1 window CFF Explorer khác và mở 1 file dotNet bất kỳ trên máy bạn để so sánh.

<p align="center">
    <img src="/assets/images/androidunpacking/6.png"/>
    <center><figcaption><b>Hình 6: So sánh Metadata Header</b></figcaption></center>
</p>


Ta vừa sửa RVA là 0x1AEDD8, tại sao trên hình, Offset lại hiện là 0x1ACFD8 ? Đó là tại vì con số đó đã được chuyển từ RVA thành FileOffset.

> FileOffset = RVA - VirtualAddress + PtrToRawData

Trong trường hợp này, **VirtualAddress** là 0x2000, **PtrToRawData** là 0x200 (2 con số này coi được ở phần Section Headers trong CFF Explorer), nên FileOffset là 0x1ACFD8. Ta đến chỗ này bằng HxD:

<p align="center">
    <img src="/assets/images/androidunpacking/7.png"/>
    <center><figcaption><b>Hình 7: Offset 0x1ACFD8</b></figcaption></center>
</p>


Kết hợp hình 6 và hình 7, ta thấy phần Metadata Header bị xoá mất Signature, MajorVersion, MinorVersion, Reserved, Flags và NumberOfStreams. Ta thêm vào 6 trường này (tổng cộng là 16 byte). Ta có thể copy thông tin từ hình bên phải vào cũng được. Sau khi sửa, ta sẽ được:

<p align="center">
    <img src="/assets/images/androidunpacking/8.png"/>
    <center><figcaption><b>Hình 8: Offset 0x1ACFD8 sau khi sửa</b></figcaption></center>
</p>


<p align="center">
    <img src="/assets/images/androidunpacking/9.png"/>
    <center><figcaption><b>Hình 9: Đến lúc này ta đã được như này</b></figcaption></center>
</p>


Giờ ta tiếp tục bấm qua phần "MetaData Streams" trong CFF Explorer.

<p align="center">
    <img src="/assets/images/androidunpacking/10.png"/>
    <center><figcaption><b>Hình 10: MetaData Streams</b></figcaption></center>
</p>


Một lần nữa ta thấy phần Offset và Size chứa những con số không hợp lý lắm. Đó là vì nó đã bị mã hoá ở hàm `load_metadata_ptrs`, ở IDA đây là hàm ở 0x1A1491:

```c++
int __cdecl load_metadata_ptrs(MonoImage *image, MonoCLIImageInfo *info)
{
   // ...
  src = &srca[n];
  v3 = src - image->raw_metadata;
  if ( (v3 & 3) != 0 )
    src += 4 - (v3 & 3);
  image->heap_tables.data = &image->raw_metadata[(*src ^ 0xF79EB7C0) - 0x7F30B650];
  image->heap_tables.size = *(src + 1) ^ 0xC8B09E5D;
  srcb = src + 8;
  image->heap_strings.data = &image->raw_metadata[(*srcb ^ 0x505ACFF1) + 0x63E4D609];
  image->heap_strings.size = *(srcb + 1) ^ 0x1E9E8832;
  srcb += 8;
  image->heap_us.data = &image->raw_metadata[(*srcb ^ 0x69198B0B) - 0x50E733C6];
  image->heap_us.size = *(srcb + 1) ^ 0x72601851;
  srcb += 8;
  image->heap_guid.data = &image->raw_metadata[(*srcb ^ 0x224E36DC) - 0x5020F714];
  image->heap_guid.size = *(srcb + 1) ^ 0x670131D5;
  srcb += 8;
  image->heap_blob.data = &image->raw_metadata[(*srcb ^ 0xC8D47FF8) + 0x2826B3F3];
  image->heap_blob.size = *(srcb + 1) ^ 0x8DB91218;
 // ...
}
```

Thông thường, 1 metadata stream table sẽ được tạo nên bởi:

- 1 DWORD Offset
- 1 DWORD Size
- Tên của stream, độ dài làm tròn cho tới khi chia hết cho 4. Những thông tin này như ở đầu bài mình nói, có thể được tham khảo ở [đây](https://www.ntcore.com/files/dotnetformat.htm).

Tuy nhiên, trong file này, phần tên stream đã bị loại bỏ. Ngoài ra Offset và Size đều bị mã hoá. Key mã hoá được hardcode ngay trong đoạn code ở trên.

<p align="center">
    <img src="/assets/images/androidunpacking/11.png"/>
    <center><figcaption><b>Hình 11: Offset và Size của 5 table bị mã hoá</b></figcaption></center>
</p>


Ta dễ dàng khôi phục lại được Offset và Size dựa vào đoạn code trên, vì nó chỉ là vài phép xor, cộng trừ cơ bản. Tên của stream đã bị xoá, ta cũng phải tự thêm vào sau mỗi cặp Offset/Size theo thứ tự sau: "#~", "#Strings", "#US", "#GUID", "#Blob". Tóm lại ta cần xoá đoạn bôi màu xanh ở trên và thêm vào đoạn sau:

<p align="center">
    <img src="/assets/images/androidunpacking/12.png"/>
    <center><figcaption><b>Hình 12: Offset, Size và Stream name sau khi mã hoá</b></figcaption></center>
</p>


Ta có được hình trên vì:

- (0x88AE0148 ^ 0xF79EB7C0) - 0x7F30B650 = 0x38
- 0xC8A145C5 ^ 0xC8B09E5D = 0x11DB98
- Tương tự chõ các phần khác ...

Sau khi làm bước trên, ta nên được như này:

<p align="center">
    <img src="/assets/images/androidunpacking/13.png"/>
    <center><figcaption><b>Hình 13: Tên stream, Offset và Size được khôi phục</b></figcaption></center>
</p>


Lúc nãy ta vừa thêm 16 byte, giờ ta vừa xoá 40 byte và thêm 76 byte, vậy tổng cộng file đã được thêm **52 byte**.

Nhưng nếu ta bấm vào phần "Strings" trong CFF Explorer, ta sẽ thấy được phần String nhìn không được ổn lắm.

<p align="center">
    <img src="/assets/images/androidunpacking/14.png"/>
    <center><figcaption><b>Hình 14: Phần string nhìn hơi sai</b></figcaption></center>
</p>


Đáng ra byte đầu tiên phải là "\x00", và đằng sau là các chuỗi ASCII. Nhưng ở đây ta lại không được như vậy. Lý do là bởi vì, nãy giờ, ta đã thêm vào file **52 byte**, vì vậy vị trí của các String cũng bị dịch chuyển ra sau **52** byte. Vậy việc ta cần làm là cộng vào tất cả các Offset ở hình 13 vào **52**.

<p align="center">
    <img src="/assets/images/androidunpacking/15.png"/>
    <center><figcaption><b>Hình 15: Cộng mỗi Offset ở hình 13 với 52</b></figcaption></center>
</p>


Lúc này phần String đã trông hợp lý hơn:

<p align="center">
    <img src="/assets/images/androidunpacking/16.png"/>
    <center><figcaption><b>Hình 16: Phần string nhìn đã hợp lý hơn</b></figcaption></center>
</p>


<p align="center">
    <img src="/assets/images/androidunpacking/17.png"/>
    <center><figcaption><b>Hình 17: Table #~ cũng đã nhận diện được các entry</b></figcaption></center>
</p>


Ngoài ra, nhìn lại **hình 5**, ta còn phần **Metadata Size** bị sai, ta phải tính lại, nó bằng tổng Offset và Size của stream cuối cùng

> 0x1B4D84 + 0x2EDF8 = 0x1E3B7C

Ta tự sửa lại **Metadata Size** thành 0x1E3B7C trong CFF và sau đó thì bỏ file vào dnSpy để decompile:

<p align="center">
    <img src="/assets/images/androidunpacking/18.png"/>
    <center><figcaption><b>Hình 18: Decompile với dnSpy</b></figcaption></center>
</p>

dnSpy đã nhận được các class, tên hàm. Tuy nhiên ...

## Stage 3: More decryption

Ta vẫn chưa thể decompile được các hàm:

<p align="center">
    <img src="/assets/images/androidunpacking/19.png"/>
    <center><figcaption><b>Hình 19: dnSpy throw exception</b></figcaption></center>
</p>


Exception được throw là **dnLib.IO.DataReaderException**. Mình thử search github thì thấy đoạn code đó nằm [ở đây](https://github.com/0xd4d/dnlib/blob/4e0837cb0f4319ffbcdd1642d1973fce203b2177/src/DotNet/ModuleDefMD.cs#L1300). Thì ra mỗi hàm đều có thông tin RVA ở trong bảng "#~"

<p align="center">
    <img src="/assets/images/androidunpacking/20.png"/>
    <center><figcaption><b>Hình 20: RVA của các hàm bị sai</b></figcaption></center>
</p>


Rõ ràng phải có chỗ nào đó chỉnh lại RVA truóc khi sử dụng. Sau khi load file, mono gọi hàm `verify_tables_data` để verify lại các table. Nó verify lại 45 table, trong đó có table số 6, sẽ được kiểm tra bằng hàm `verify_method_table`:

Code gốc:

```c++
static void
verify_method_table (VerifyContext *ctx)
{
    // ...
	for (i = 0; i < table->rows; ++i) {
		mono_metadata_decode_row (table, i, data, MONO_METHOD_SIZE);
		rva = data [MONO_METHOD_RVA];
		implflags = data [MONO_METHOD_IMPLFLAGS];
		flags = data [MONO_METHOD_FLAGS];
		access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
		code_type = implflags & METHOD_IMPL_ATTRIBUTE_CODE_TYPE_MASK;
        // ...
    }
}
```

IDA:

```c++
VerifyContext *__cdecl method_check(VerifyContext *a1)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]
  table = &a1->image->tables[6];
  v75 = 1;
  v76 = -1;
  if ( (*(&a1->image->tables[2] + 1) & 0xFFFFFFu) > 1 )
  {
    type = &a1->image->tables[2];
    v76 = mono_metadata_decode_row_col(type, 1, 5u);
  }
  for ( i = 0; ; ++i )
  {
    result = (*(table + 1) & 0xFFFFFF);
    if ( result <= i )
      break;
    mono_metadata_decode_row(table, i, v33, 6);
    rva = (v33[0] ^ 0xDF764784) + 0x2D14B230;   // <------ ????
    v70 = v33[1];
    v69 = v33[2];
    v68 = v33[2] & 7;
    v67 = v33[1] & 3;
    v66 = v33[3];
}
```

Ta có thể thấy RVA đã bị mã hoá, ta có thể dễ dàng viết đoạn code để khôi phục nó lại, chỉ cần lấy (RVA ^ 0xDF764784) + 0x2D14B230.

<p align="center">
    <img src="/assets/images/androidunpacking/21.png"/>
    <center><figcaption><b>Hình 21: RVA sau khi sửa</b></figcaption></center>
</p>


Mặc dù sửa xong như vậy nhưng dnSpy vẫn không thể decompile các hàm.

## Stage 4: Custom CIL VM

Giờ ta đến thử hàm đầu tiên (RID = 1) xem sao, RVA = 0x145E4 -> File Offset = 0x127E4.

<p align="center">
    <img src="/assets/images/androidunpacking/22.png"/>
    <center><figcaption><b>Hình 22: Offset 0x127E4</b></figcaption></center>
</p>


Cấu trúc của 1 method trong dotNet là, nếu byte đầu tiên có 2 bit nhỏ nhất là **0b10**, thì 6 bit còn lại sẽ là size của code. Giá trị trong hình là 0x5E , 0x5E & 3 = 0x2 = 0b10 nên code size là 0x5E >> 2 = 0x17. Vậy hàm này bắt đầu từ 0x145E4 và kết thúc tại 0x145E4 + 0x17 = 0x145FB. Điều này là vô lý vì hàm số 2 bắt đầu tại 0x145ED, không lẽ 2 hàm này đè lên nhau ? Thật ra con số này cũng bị mã hoá luôn, bằng chứng là ở hàm `mono_metadata_parse_mh_full`:

```c++
int __cdecl mono_metadata_parse_mh_full(MonoImage *a1, int a2, const char *hdr_ptr)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  hdr_val = *hdr_ptr ^ 0x7C;
 // ...
}
```

Nó được xor với 0x7C trước khi sử dụng, ta có thể dễ dàng sửa lại. Giờ ta thử: 0x5E ^ 0x7C = 0x22. 0x22 có hai byte nhỏ nhất là 0b10, nên code size là 0x22 >> 2 = 0x8. Vậy hàm này bắt đầu ở 0x145E4 và kết thúc tại 0x145E4 + 0x8 = 0x145EC. Quá hoàn hảo vì hàm tiếp theo bắt đầu tại 0x145ED.

Sau khi sửa, dnSpy vẫn không decompile được, vẫn throw exception. Ta quay lại FileOffset 0x127E4 xem đoạn code CIL. Như tính toán ở trên, đoạn code có size là 0x8 byte, như trên **hình 22**, 8 byte đó là "9F 18 31 00 00 0A 2A 02". Thông thường, mình để ý với các hàm nhỏ thì byte cuối cùng phải là **2A** mới đúng, bởi vì **2A** là opcode của "return" ([tham khảo ở đây](https://en.wikipedia.org/wiki/List_of_CIL_instructions)). Nhưng đoạn code trên lại có byte cuối là **02**. Điều này làm mình nghĩ tới việc, thư viện mono này đã bị thay đổi các opcode.

Đến đây, mình đã setup máy ảo MEmu, dùng IDA đặt hardware breakpoint on access lên đoạn code để xem hàm nào sử dụng đoạn code của mình, thì breakpoint hit ngay tại giữa 1 hàm rất lớn. Hàm này có một đoạn switch case rất dài, đó chính là hàm `mono_method_to_ir`. Hàm này làm công việc đọc opcode, rồi chuyển code CIL đó sang native code. Đây là chỗ mà VM được cài đặt, trong source code, trông nó như này:

```c++
while (ip < end) {
    switch (*ip) {
        case CEE_NOP:
            // ....
            ip++; break;
        case CEE_BREAK:
            // ...
    }
}
```

Việc khôi phục lại các opcode khá khó khăn, phải so sánh code trong IDA với source code để tìm ra opcode đúng. Tuy nhiên nó quá nhiều case, làm rất mất thời gian. Vì vậy mình đã thử tải phiên bản cũ của game thì thấy bản 1.6.1 chưa bị mã hoá **Assembly-CSharp.dll**. Mình thử so sánh hai hàm có RID = 2 thì thấy code như sau:

- Hàm ở bản 1.6.1: "02 7E 02 00 00 0A 28 03 00 00 06 2A"
- Hàm ở bản 1.6.7: "9F 06 32 00 00 0A 18 03 00 00 06 02"

Ta có thể thấy opcode 02 đã bị đổi thành 9F, 7E bị đổi thành 06, 28 bị đổi thành 18 và 2A bị đổi thành 02. Biết được điều này, mình chỉ việc đổi ngược lại là xong.

<p align="center">
    <img src="/assets/images/androidunpacking/23.png"/>
    <center><figcaption><b>Hình 23: Sau khi sửa lại opcode, dnSpy đã decompile được</b></figcaption></center>
</p>


Vậy là mình đã unpack thành công mono library được sử dụng bởi con game này. Hiện tại thì game đã được cập nhật lên bản 1.7.0, nó cũng đã chuyển sang sử dụng **IL2cpp**, tức là phương pháp unpack trên không còn dùng được nữa. Tuy nhiên ta có thể sử dụng công cụ khác để hack, nhưng có lẽ mình sẽ viết về nó sau.

<div style="text-align: right"> Happy hacking, and happy new year ! </div>