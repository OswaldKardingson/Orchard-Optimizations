// Copyright (c) 2022-2023 The Zcash developers
// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ZCASH_ZCASH_MEMO_H
#define ZCASH_ZCASH_MEMO_H

#include <tl/expected.hpp>
#include <array>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace libzcash
{

/// Memos are described in the Zcash Protocol Specification §§ 3.2.1 & 5.5 and ZIP 302.
///
/// Memos are generally wrapped in `std::optional` with the special “no memo” byte string of
/// `0xF60000…00`  represented as `std::nullopt`. This is why some static
/// members handle `std::optional<Memo>` instead of `Memo` directly.
class Memo
{
public:
    static constexpr size_t SIZE = 512;

    using Byte = unsigned char;
    using Bytes = std::array<Byte, SIZE>;

    /// Represents memo contents with no interpretation.
    using FutureData = Bytes;

    /// Arbitrary data prefixed by `0xFF`. The size must be `SIZE - 1` since the prefix occupies the first byte.
    using ArbitraryData = std::array<Byte, SIZE - 1>;

    /// The possible interpretations of a memo’s content.
    using Contents = std::variant<
        /// UTF-8 string for memos where the first byte is `<= 0xF4`.
        std::string,
        /// Future data (values between `0xF5` and `0xFE`).
        FutureData,
        /// Arbitrary data prefixed with `0xFF`.
        ArbitraryData>;

private:
    Bytes value_;

    static constexpr Bytes noMemo = {0xf6};

    /// Constructs a memo assuming the provided value is valid.
    explicit Memo(Bytes value) : value_(value) {}

public:
    /// Possible conversion errors for memo creation.
    enum class ConversionError {
        MemoTooLong,
    };

    /// Possible text conversion errors.
    enum class TextConversionError {
        MemoTooLong,
        InvalidUTF8,
    };

    /// Possible errors during memo interpretation.
    enum class InterpretationError {
        InvalidUTF8,
    };

    /// Creates a memo from arbitrary data, always prefixed with `0xFF`.
    explicit Memo(const ArbitraryData& data);

    /// Equality operators.
    friend bool operator==(const Memo& a, const Memo& b) = default;
    friend bool operator!=(const Memo& a, const Memo& b) = default;

    /// Converts raw bytes into a `Memo` if valid.
    static std::optional<Memo> FromBytes(const Bytes& rawMemo);

    static std::optional<Memo> FromBytes(const Byte (&rawMemo)[SIZE]);

    static tl::expected<std::optional<Memo>, ConversionError>
    FromBytes(const std::vector<Byte>& rawMemo);

    /// Converts UTF-8 encoded text into a `Memo`.
    static tl::expected<Memo, TextConversionError> FromText(const std::string& memoStr);

    /// Retrieves the raw bytes of the memo.
    [[nodiscard]] const Bytes& ToBytes() const;

    /// Retrieves the raw bytes of an optional memo or `noMemo`.
    [[nodiscard]] static const Bytes& ToBytes(const std::optional<Memo>& memo);

    /// Interprets the memo according to ZIP 302 specification.
    [[nodiscard]] tl::expected<Contents, InterpretationError> Interpret() const;
};

} // namespace libzcash

#endif // ZCASH_ZCASH_MEMO_H
