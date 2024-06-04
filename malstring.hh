#pragma once

#include <type_traits>
#include <ranges>
#include <algorithm>
#include <string_view>
#include <charconv>
#include <cstdint>
#include <cstddef>


#if (defined(_MSC_VER))
#define NOINLINE __declspec(noinline)
#define FORCEINLINE __forceinline
#else
#define NOINLINE __attribute__((noinline))
#define FORCEINLINE __attribute__((always_inline))
#endif


#define TIME_SEED ((__TIME__[7] - '0') * 1	+ (__TIME__[6] - '0') * 10  + \
					   (__TIME__[4] - '0') * 60   + (__TIME__[3] - '0') * 600 + \
					   (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000)

constexpr std::uint32_t Modulus()
{
	return 0x7fffffff;
}

template <std::size_t N>
consteval std::uint32_t Seed(const char(&Entropy)[N], const std::uint32_t Iv = 0)
{
	auto Value{ Iv };
	for (std::size_t i{ 0 }; i < N; i++)
	{
		Value = (Value & ((~0) << 8)) | ((Value & 0xFF) ^ Entropy[i]);
		Value = Value << 8 | Value >> ((sizeof(Value) * 8) - 8);
	}
	while (Value > Modulus())
		Value = Value >> 1;
	return Value << 1 | 1;
}

constexpr std::uint32_t prng(const std::uint32_t Input)
{
	return (Input * 48271) % Modulus();
}

#define RAND() (Seed(__FILE__, __COUNTER__ + __LINE__ * TIME_SEED))


template <std::size_t Size, typename CharType>
struct FixedString
{
	consteval FixedString(const CharType(&Str)[Size]) noexcept
	{
		for (std::size_t i = 0; i < Size; ++i)
		{
			this->Buf[i] = Str[i];
		}
	}

	static constexpr std::size_t Len = Size;
	CharType Buf[Size];

	constexpr operator std::string_view() const noexcept
	{
		return { Buf, Len - 1 };
	}
};

template <FixedString Fixed, std::uint32_t Rand>
class StackString
{
public:
	consteval StackString()
	{
		static_assert(
			std::is_same_v<std::remove_cv_t<std::remove_reference_t<decltype(Fixed.Buf[0])>>, char> ||
			std::is_same_v<std::remove_cv_t<std::remove_reference_t<decltype(Fixed.Buf[0])>>, wchar_t> ||
			std::is_same_v<std::remove_cv_t<std::remove_reference_t<decltype(Fixed.Buf[0])>>, char16_t> ||
			std::is_same_v<std::remove_cv_t<std::remove_reference_t<decltype(Fixed.Buf[0])>>, char32_t>
			);

		for (std::size_t i = 0; i < Fixed.Len; ++i)
		{
			Buf[i] = Fixed.Buf[i] ^ (Rand + static_cast<std::uint32_t>(i));
		}
	}


	FORCEINLINE void EncryptDecrypt()
	{
		for (std::size_t i = 0; i < Fixed.Len; ++i)
		{
			Buf[i] = Buf[i] ^ (Rand + static_cast<std::uint32_t>(i));
		}
	}

	consteval std::size_t Length()
	{
		return Fixed.Len;
	}

	std::remove_cv_t<std::remove_reference_t<decltype(Fixed.Buf[0])>> Buf[Fixed.Len];
};


template <auto C>
auto NOINLINE CallNum()
{
	return C;
}

template <FixedString Fixed, std::uint32_t Rand, bool IsTerm = true, std::size_t N = Fixed.Len - (IsTerm ? 1 : 2)>
FORCEINLINE void MakeCallString(std::remove_cv_t<std::remove_reference_t<decltype(Fixed.Buf[0])>>* Buf)
{
	Buf[N] = static_cast<std::uint8_t>(CallNum<Fixed.Buf[N] ^ (Rand + static_cast<std::uint32_t>(N))>());

	if constexpr (N)
		MakeCallString<Fixed, Rand, IsTerm, N - 1>(Buf);
}

template <FixedString Fixed, std::uint32_t Rand, bool IsTerm = true>
class CallString
{
public:
	FORCEINLINE CallString()
	{
		MakeCallString<Fixed, Rand, IsTerm>(Buf);
	}

	FORCEINLINE void EncryptDecrypt()
	{
		for (std::size_t i = 0; i < Fixed.Len - (IsTerm ? 0 : 1); ++i)
		{
			Buf[i] = Buf[i] ^ static_cast<std::uint8_t>(Rand + static_cast<std::uint32_t>(i));
		}
	}

	std::remove_cv_t<std::remove_reference_t<decltype(Fixed.Buf[0])>> Buf[Fixed.Len - (IsTerm ? 0 : 1)];
};


constexpr auto to_int = [](std::string_view sv) -> std::uint8_t
	{
		std::uint8_t value{};
		const auto res = std::from_chars(sv.data(), sv.data() + sv.size(), value, 16);
		return value;
	};

constexpr auto to_sv = [](auto&& rng) { return std::string_view(rng); };

template <FixedString Pattern>
constexpr auto hex2array() -> std::array<std::uint8_t, Pattern.Len / 3>
{
	const std::size_t ArrSize = Pattern.Len / 3;
	constexpr auto pat = std::string_view{ Pattern };
	std::array<std::uint8_t, ArrSize> res{};

	static_assert(std::ranges::distance(std::views::split(pat, ' ')) == ArrSize);

	for (std::size_t i{};
		const auto byte : std::views::split(pat, ' ')
		| std::views::transform(to_sv)
		| std::views::transform(to_int))
	{
		res.at(i++) = byte;
	}

	return res;
}

template <std::size_t ArraySize, std::array<std::uint8_t, ArraySize> Array, std::uint32_t Rand, std::size_t N =
	ArraySize - 1>
FORCEINLINE void MakeCallBuffer(std::uint8_t* Buf)
{
	Buf[N] = static_cast<std::uint8_t>(CallNum<Array[N] ^ (Rand + static_cast<std::uint32_t>(N))>());

	if constexpr (N)
		MakeCallBuffer<ArraySize, Array, Rand, N - 1>(Buf);
}

template <std::size_t ArraySize, std::array<std::uint8_t, ArraySize> Array, std::uint32_t Rand>
class CallArray
{
public:
	FORCEINLINE CallArray()
	{
		MakeCallBuffer<ArraySize, Array, Rand>(Buf);
	}

	FORCEINLINE void EncryptDecrypt()
	{
		for (std::size_t i = 0; i < ArraySize; ++i)
		{
			Buf[i] = Buf[i] ^ static_cast<std::uint8_t>(Rand + static_cast<std::uint32_t>(i));
		}
	}

	std::uint8_t Buf[ArraySize];
};

template <FixedString Fixed, std::uint32_t Rand>
class CallArrayFromHex
{
public:
	FORCEINLINE CallArrayFromHex()
	{
		constexpr std::array<std::uint8_t, Fixed.Len / 3> Mask = hex2array<Fixed>();
		MakeCallBuffer<Fixed.Len / 3, Mask, Rand>(Buf);
	}

	FORCEINLINE void EncryptDecrypt()
	{
		for (std::size_t i = 0; i < (Fixed.Len - 1) / 3; ++i)
		{
			Buf[i] = Buf[i] ^ (Rand + static_cast<std::uint32_t>(i));
		}
	}

	std::uint8_t Buf[(Fixed.Len - 1) / 3];
};
