// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "zcash/memo.h"

#include <utf8cpp/utf8.h>
#include <algorithm>
#include <array>

namespace libzcash {

Memo::Memo(const ArbitraryData& data) : value_({0xff}) 
{
    // Use std::copy for safer memory operations
    std::copy(data.begin(), data.end(), value_.begin() + 1);
}

bool operator==(const Memo& a, const Memo& b)
{
    return a.value_ == b.value_;
}

bool operator!=(const Memo& a, const Memo& b)
{
    return !(a == b);
}

std::optional<Memo> Memo::FromBytes(const Bytes& rawMemo)
{
    if (rawMemo == noMemo) {
        return std::nullopt;
    }
    return Memo(rawMemo);
}

std::optional<Memo> Memo::FromBytes(const Byte (&rawMemo)[SIZE])
{
    Bytes result{}; // Ensure the array is zero-initialized
    std::copy(std::begin(rawMemo), std::end(rawMemo), result.begin());
    return FromBytes(result);
}

tl::expected<std::optional<Memo>, Memo::ConversionError>
Memo::FromBytes(const std::vector<Byte>& rawMemo)
{
    if (rawMemo.size() > SIZE) {
        return tl::unexpected(ConversionError::MemoTooLong);
    }
    
    Bytes result{};
    // Use std::copy for safer memory operations
    std::copy(rawMemo.begin(), rawMemo.end(), result.begin());
    return FromBytes(result);
}

tl::expected<Memo, Memo::TextConversionError> Memo::FromText(const std::string& memoStr)
{
    if (!utf8::is_valid(memoStr)) {
        return tl::unexpected(TextConversionError::InvalidUTF8);
    }

    if (memoStr.size() > SIZE) {
        return tl::unexpected(TextConversionError::MemoTooLong);
    }

    Bytes result{};
    // Use std::copy for text conversion to bytes
    std::copy(memoStr.begin(), memoStr.end(), result.begin());
    return Memo(result);
}

const Memo::Bytes& Memo::ToBytes() const
{
    return value_;
}

const Memo::Bytes& Memo::ToBytes(const std::optional<Memo>& memo)
{
    return memo.has_value() ? memo.value().ToBytes() : noMemo;
}

tl::expected<Memo::Contents, Memo::InterpretationError> Memo::Interpret() const
{
    // If the leading byte is 0xF4 or lower, the memo field should be interpreted as a
    // UTF-8-encoded text string.
    if (value_[0] <= 0xf4) {
        // Trim off trailing zeroes
        auto end = std::find_if(value_.rbegin(), value_.rend(), [](auto v) { return v != 0; });
        std::string memoStr(value_.begin(), end.base());
        if (!utf8::is_valid(memoStr)) {
            return tl::unexpected(InterpretationError::InvalidUTF8);
        }
        return {memoStr};
    }

    if (value_[0] == 0xff) {
        ArbitraryData data;
        // Use std::copy for safer memory operations
        std::copy(value_.begin() + 1, value_.end(), data.begin());
        return data;
    }

    // Default case for uninterpreted values
    return value_;
}
