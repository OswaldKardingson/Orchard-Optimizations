// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#ifndef BITCOIN_STREAMS_H
#define BITCOIN_STREAMS_H

#include "serialize.h"
#include "support/allocators/secure.h"
#include "support/allocators/zeroafterfree.h"

#include <algorithm>
#include <assert.h>
#include <ios>
#include <limits>
#include <map>
#include <set>
#include <stdint.h>
#include <stdio.h>
#include <string>
#include <utility>
#include <vector>

/**
 * Wrapper around C++ stream objects, enabling them to be passed into Rust code.
 */
template <typename Stream>
class RustStream
{
    Stream* stream;

public:
    RustStream(Stream& stream_) : stream(&stream_) {}

    static long read_callback(void* context, std::vector<unsigned char>& buffer, size_t nSize)
    {
        return reinterpret_cast<RustStream*>(context)->read(
            reinterpret_cast<std::vector<char>&>(buffer), nSize);
    }

    static long write_callback(void* context, const std::vector<unsigned char>& buffer, size_t nSize)
    {
        return reinterpret_cast<RustStream*>(context)->write(
            reinterpret_cast<const std::vector<char>&>(buffer), nSize);
    }

    long read(std::vector<char>& buffer, size_t nSize)
    {
        try {
            stream->read(buffer.data(), nSize);
            return nSize;
        } catch (std::ios_base::failure e) {
            // TODO: log
            return -1;
        }
    }

    long write(const std::vector<char>& buffer, size_t nSize)
    {
        try {
            stream->write(buffer.data(), nSize);
            return nSize;
        } catch (std::ios_base::failure e) {
            // TODO: log
            return -1;
        }
    }
};

template <typename Stream>
class OverrideStream
{
    Stream* stream;

    const int nType;
    const int nVersion;

public:
    OverrideStream(Stream* stream_, int nType_, int nVersion_)
        : stream(stream_), nType(nType_), nVersion(nVersion_) {}

    template <typename T>
    OverrideStream<Stream>& operator<<(const T& obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }

    template <typename T>
    OverrideStream<Stream>& operator>>(T&& obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return (*this);
    }

    void write(const char* pch, size_t nSize)
    {
        if (pch != nullptr && nSize > 0) {
            stream->write(pch, nSize);
        } else {
            throw std::ios_base::failure("OverrideStream::write(): Invalid write operation.");
        }
    }

    void read(char* pch, size_t nSize)
    {
        if (pch != nullptr && nSize > 0) {
            stream->read(pch, nSize);
        } else {
            throw std::ios_base::failure("OverrideStream::read(): Invalid read operation.");
        }
    }

    int GetVersion() const { return nVersion; }
    int GetType() const { return nType; }
    size_t size() const { return stream->size(); }
    void ignore(size_t size) { return stream->ignore(size); }
};

template <typename S>
OverrideStream<S> WithVersion(S* s, int nVersion)
{
    return OverrideStream<S>(s, s->GetType(), nVersion);
}

/* Minimal stream for overwriting and/or appending to an existing byte vector
 *
 * The referenced vector will grow as necessary
 */
class CVectorWriter
{
public:
    /*
     * @param[in]  nTypeIn Serialization Type
     * @param[in]  nVersionIn Serialization Version (including any flags)
     * @param[in]  vchDataIn  Referenced byte vector to overwrite/append
     * @param[in]  nPosIn Starting position. Vector index where writes should start.
     *                    The vector will initially grow as necessary to max(nPosIn, vec.size()).
     *                    So to append, use vec.size().
     */
    CVectorWriter(int nTypeIn, int nVersionIn, std::vector<unsigned char>& vchDataIn, size_t nPosIn)
        : nType(nTypeIn), nVersion(nVersionIn), vchData(vchDataIn), nPos(nPosIn)
    {
        if (nPos > vchData.size()) {
            vchData.resize(nPos); // Pre-allocate memory if needed
        }
    }

    /*
     * (other params same as above)
     * @param[in]  args  A list of items to serialize starting at nPosIn.
     */
    template <typename... Args>
    CVectorWriter(int nTypeIn, int nVersionIn, std::vector<unsigned char>& vchDataIn, size_t nPosIn, Args&&... args)
        : CVectorWriter(nTypeIn, nVersionIn, vchDataIn, nPosIn)
    {
        ::SerializeMany(*this, std::forward<Args>(args)...);
    }

    void write(const char* pch, size_t nSize)
    {
        if (pch == nullptr || nSize == 0) {
            throw std::ios_base::failure("CVectorWriter::write(): Invalid write operation.");
        }

        // Ensure sufficient capacity
        if (nPos + nSize > vchData.capacity()) {
            vchData.reserve(nPos + nSize);
        }

        assert(nPos <= vchData.size());
        size_t nOverwrite = std::min(nSize, vchData.size() - nPos);
        if (nOverwrite) {
            std::copy(pch, pch + nOverwrite, vchData.begin() + nPos);
        }
        if (nOverwrite < nSize) {
            vchData.insert(vchData.end(), pch + nOverwrite, pch + nSize);
        }
        nPos += nSize;
    }

    template <typename T>
    CVectorWriter& operator<<(const T& obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }

    int GetVersion() const { return nVersion; }
    int GetType() const { return nType; }

private:
    const int nType;
    const int nVersion;
    std::vector<unsigned char>& vchData;
    size_t nPos;
};

/**
 * Double-ended buffer combining vector and stream-like interfaces.
 *
 * >> and << read and write unformatted data using the above serialization templates.
 * Fills with data in linear time; some stringstream implementations take N^2 time.
 */
template <typename SerializeType>
class CBaseDataStream
{
protected:
    using vector_type = SerializeType;
    vector_type vch;
    unsigned int nReadPos;

    int nType;
    int nVersion;

public:
    using allocator_type = typename vector_type::allocator_type;
    using size_type = typename vector_type::size_type;
    using difference_type = typename vector_type::difference_type;
    using reference = typename vector_type::reference;
    using const_reference = typename vector_type::const_reference;
    using value_type = typename vector_type::value_type;
    using iterator = typename vector_type::iterator;
    using const_iterator = typename vector_type::const_iterator;
    using reverse_iterator = typename vector_type::reverse_iterator;

    explicit CBaseDataStream(int nTypeIn, int nVersionIn)
    {
        Init(nTypeIn, nVersionIn);
    }

    CBaseDataStream(const_iterator pbegin, const_iterator pend, int nTypeIn, int nVersionIn)
        : vch(pbegin, pend)
    {
        Init(nTypeIn, nVersionIn);
    }

    CBaseDataStream(const char* pbegin, const char* pend, int nTypeIn, int nVersionIn)
        : vch(pbegin, pend)
    {
        Init(nTypeIn, nVersionIn);
    }

    CBaseDataStream(const vector_type& vchIn, int nTypeIn, int nVersionIn)
        : vch(vchIn.begin(), vchIn.end())
    {
        Init(nTypeIn, nVersionIn);
    }

    template <size_t _N>
    CBaseDataStream(const std::array<unsigned char, _N>& vchIn, int nTypeIn, int nVersionIn)
        : vch(vchIn.begin(), vchIn.end())
    {
        Init(nTypeIn, nVersionIn);
    }

    template <typename... Args>
    CBaseDataStream(int nTypeIn, int nVersionIn, Args&&... args)
    {
        Init(nTypeIn, nVersionIn);
        ::SerializeMany(*this, std::forward<Args>(args)...);
    }

    void Init(int nTypeIn, int nVersionIn)
    {
        nReadPos = 0;
        nType = nTypeIn;
        nVersion = nVersionIn;

        // Pre-allocate memory to minimize resizing during operations
        vch.reserve(1024); // Example pre-allocation for typical usage
    }

    CBaseDataStream& operator+=(const CBaseDataStream& b)
    {
        vch.insert(vch.end(), b.begin(), b.end());
        return *this;
    }

    friend CBaseDataStream operator+(const CBaseDataStream& a, const CBaseDataStream& b)
    {
        CBaseDataStream ret = a;
        ret += b;
        return ret;
    }

    std::string str() const
    {
        return std::string(begin(), end());
    }

    //
    // Vector subset
    //
    const_iterator begin() const { return vch.begin() + nReadPos; }
    iterator begin() { return vch.begin() + nReadPos; }
    const_iterator end() const { return vch.end(); }
    iterator end() { return vch.end(); }
    size_type size() const { return vch.size() - nReadPos; }
    bool empty() const { return vch.size() == nReadPos; }
    void resize(size_type n, value_type c = 0)
    {
        vch.resize(n + nReadPos, c);
    }
    void reserve(size_type n)
    {
        vch.reserve(n + nReadPos);
    }
    const_reference operator[](size_type pos) const { return vch[pos + nReadPos]; }
    reference operator[](size_type pos) { return vch[pos + nReadPos]; }
    void clear()
    {
        vch.clear();
        nReadPos = 0;
    }

    iterator insert(iterator it, const char& x = char())
    {
        return vch.insert(it, x);
    }

    void insert(iterator it, size_type n, const char& x)
    {
        vch.insert(it, n, x);
    }

    value_type* data() { return vch.data() + nReadPos; }
    const value_type* data() const { return vch.data() + nReadPos; }
};

    void insert(iterator it, const char* first, const char* last)
    {
        if (last == first)
            return;
        assert(last - first > 0);
        if (it == vch.begin() + nReadPos && static_cast<size_type>(last - first) <= nReadPos) {
            // Special case for inserting at the front when there's room
            nReadPos -= (last - first);
            std::copy(first, last, &vch[nReadPos]);
        } else {
            vch.insert(it, first, last);
        }
    }

    iterator erase(iterator it)
    {
        if (it == vch.begin() + nReadPos) {
            // Special case for erasing from the front
            if (++nReadPos >= vch.size()) {
                // Whenever we reach the end, we take the opportunity to clear the buffer
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            }
            return vch.begin() + nReadPos;
        } else {
            return vch.erase(it);
        }
    }

    iterator erase(iterator first, iterator last)
    {
        if (first == vch.begin() + nReadPos) {
            // Special case for erasing from the front
            if (last == vch.end()) {
                nReadPos = 0;
                return vch.erase(vch.begin(), vch.end());
            } else {
                nReadPos = (last - vch.begin());
                return last;
            }
        } else {
            return vch.erase(first, last);
        }
    }

    inline void Compact()
    {
        if (nReadPos > 0) {
            // Only compact if necessary
            vch.erase(vch.begin(), vch.begin() + nReadPos);
            nReadPos = 0;
        }
    }

    bool Rewind(size_type n)
    {
        // Rewind by n characters if the buffer hasn't been compacted yet
        if (n > nReadPos)
            return false;
        nReadPos -= n;
        return true;
    }

    //
    // Stream subset
    //
    bool eof() const { return size() == 0; }
    CBaseDataStream* rdbuf() { return this; }
    int in_avail() { return size(); }

    void SetType(int n) { nType = n; }
    int GetType() const { return nType; }
    void SetVersion(int n) { nVersion = n; }
    int GetVersion() const { return nVersion; }

    void read(char* pch, size_t nSize)
    {
        if (nSize == 0)
            return;

        if (pch == nullptr) {
            throw std::ios_base::failure("CBaseDataStream::read(): cannot read from null pointer");
        }

        // Read from the beginning of the buffer
        size_type nReadPosNext = nReadPos + nSize;
        if (nReadPosNext > vch.size()) {
            throw std::ios_base::failure("CBaseDataStream::read(): end of data");
        }
        std::copy(vch.begin() + nReadPos, vch.begin() + nReadPosNext, pch);
        nReadPos = nReadPosNext;
    }

    void ignore(int nSize)
    {
        if (nSize < 0) {
            throw std::ios_base::failure("CBaseDataStream::ignore(): nSize negative");
        }

        // Ignore from the beginning of the buffer
        size_type nReadPosNext = nReadPos + nSize;
        if (nReadPosNext > vch.size()) {
            throw std::ios_base::failure("CBaseDataStream::ignore(): end of data");
        }
        nReadPos = nReadPosNext;
    }

    void write(const char* pch, size_t nSize)
    {
        if (pch == nullptr || nSize == 0) {
            throw std::ios_base::failure("CBaseDataStream::write(): Invalid write operation");
        }

        // Write to the end of the buffer
        vch.insert(vch.end(), pch, pch + nSize);
    }

    template <typename T>
    CBaseDataStream& operator<<(const T& obj)
    {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return *this;
    }

    template <typename T>
    CBaseDataStream& operator>>(T&& obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return *this;
    }
};

    void GetAndClear(CSerializeData& d)
    {
        // Move data to the provided container and clear the internal buffer
        d.insert(d.end(), begin(), end());
        clear();
    }
};

class CDataStream : public CBaseDataStream<CSerializeData>
{
public:
    explicit CDataStream(int nTypeIn, int nVersionIn)
        : CBaseDataStream(nTypeIn, nVersionIn) {}

    CDataStream(const_iterator pbegin, const_iterator pend, int nTypeIn, int nVersionIn)
        : CBaseDataStream(pbegin, pend, nTypeIn, nVersionIn) {}

    CDataStream(const char* pbegin, const char* pend, int nTypeIn, int nVersionIn)
        : CBaseDataStream(pbegin, pend, nTypeIn, nVersionIn) {}

    CDataStream(const vector_type& vchIn, int nTypeIn, int nVersionIn)
        : CBaseDataStream(vchIn, nTypeIn, nVersionIn) {}

    template <size_t _N>
    CDataStream(const std::array<unsigned char, _N>& vchIn, int nTypeIn, int nVersionIn)
        : CBaseDataStream(vchIn, nTypeIn, nVersionIn) {}

    template <typename... Args>
    CDataStream(int nTypeIn, int nVersionIn, Args&&... args)
        : CBaseDataStream(nTypeIn, nVersionIn, args...) {}
};

/**
 * Concrete instantiation of a data stream, enabling them to be passed into Rust code.
 *
 * TODO: Rename this to RustStream once the non-`cxx` usages have been migrated to `cxx`.
 */
typedef CBaseDataStream<CSerializeData> RustDataStream;

typedef std::vector<unsigned char, secure_allocator<unsigned char>> CKeyingMaterial;

class CSecureDataStream : public CBaseDataStream<CKeyingMaterial>
{
public:
    explicit CSecureDataStream(int nTypeIn, int nVersionIn)
        : CBaseDataStream(nTypeIn, nVersionIn) {}

    CSecureDataStream(const_iterator pbegin, const_iterator pend, int nTypeIn, int nVersionIn)
        : CBaseDataStream(pbegin, pend, nTypeIn, nVersionIn) {}

    CSecureDataStream(const vector_type& vchIn, int nTypeIn, int nVersionIn)
        : CBaseDataStream(vchIn, nTypeIn, nVersionIn) {}

    template <size_t _N>
    CSecureDataStream(const std::array<unsigned char, _N>& vchIn, int nTypeIn, int nVersionIn)
        : CBaseDataStream(vchIn, nTypeIn, nVersionIn) {}
};

/**
 * Concrete instantiation of a data stream, enabling them to be passed into Rust code.
 *
 * TODO: Rename this to RustStream once the non-`cxx` usages have been migrated to `cxx`.
 */
typedef CBaseDataStream<CKeyingMaterial> SecureRustDataStream;

/** Non-refcounted RAII wrapper for FILE*
 *
 * Will automatically close the file when it goes out of scope if not null.
 * If you're returning the file pointer, return file.release().
 * If you need to close the file early, use file.fclose() instead of fclose(file).
 */
class CAutoFile
{
private:
    // Disallow copies
    CAutoFile(const CAutoFile&) = delete;
    CAutoFile& operator=(const CAutoFile&) = delete;

    const int nType;
    const int nVersion;

    FILE* file;

public:
    CAutoFile(FILE* filenew, int nTypeIn, int nVersionIn)
        : nType(nTypeIn), nVersion(nVersionIn), file(filenew) {}

    ~CAutoFile()
    {
        fclose();
    }

    void fclose()
    {
        if (file) {
            ::fclose(file);
            file = nullptr;
        }
    }

    /** Get wrapped FILE* with transfer of ownership.
     * @note This will invalidate the CAutoFile object, and makes it the responsibility of the caller
     * of this function to clean up the returned FILE*.
     */
    FILE* release()
    {
        FILE* ret = file;
        file = nullptr;
        return ret;
    }

    /** Get wrapped FILE* without transfer of ownership.
     * @note Ownership of the FILE* will remain with this class. Use this only if the scope of the
     * CAutoFile outlives use of the passed pointer.
     */
    FILE* Get() const { return file; }

    /** Return true if the wrapped FILE* is NULL, false otherwise.
     */
    bool IsNull() const { return (file == nullptr); }

    //
    // Stream subset
    //
    int GetType() const { return nType; }
    int GetVersion() const { return nVersion; }

    void read(char* pch, size_t nSize)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::read: file handle is NULL");
        if (fread(pch, 1, nSize, file) != nSize)
            throw std::ios_base::failure(feof(file) ? "CAutoFile::read: end of file" : "CAutoFile::read: fread failed");
    }

    void write(const char* pch, size_t nSize)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::write: file handle is NULL");
        if (fwrite(pch, 1, nSize, file) != nSize)
            throw std::ios_base::failure("CAutoFile::write: write failed");
    }
};

    void ignore(size_t nSize)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::ignore: file handle is NULL");
        unsigned char data[4096];
        while (nSize > 0) {
            size_t nNow = std::min<size_t>(nSize, sizeof(data));
            if (fread(data, 1, nNow, file) != nNow) {
                throw std::ios_base::failure(feof(file) ? "CAutoFile::ignore: end of file"
                                                        : "CAutoFile::ignore: fread failed");
            }
            nSize -= nNow;
        }
    }

    template <typename T>
    CAutoFile& operator<<(const T& obj)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::operator<<: file handle is NULL");

        // Serialize to this stream
        ::Serialize(*this, obj);
        return *this;
    }

    template <typename T>
    CAutoFile& operator>>(T& obj)
    {
        if (!file)
            throw std::ios_base::failure("CAutoFile::operator>>: file handle is NULL");

        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return *this;
    }
};

/** Non-refcounted RAII wrapper around a FILE* that implements a ring buffer to
 *  deserialize from. It guarantees the ability to rewind a given number of bytes.
 *
 *  Will automatically close the file when it goes out of scope if not null.
 *  If you need to close the file early, use file.fclose() instead of fclose(file).
 */
class CBufferedFile
{
private:
    // Disallow copies
    CBufferedFile(const CBufferedFile&) = delete;
    CBufferedFile& operator=(const CBufferedFile&) = delete;

    const int nType;
    const int nVersion;

    FILE* src;                // source file
    uint64_t nSrcPos;         // how many bytes have been read from source
    uint64_t nReadPos;        // how many bytes have been read from this
    uint64_t nReadLimit;      // up to which position we're allowed to read
    uint64_t nRewind;         // how many bytes we guarantee to rewind
    std::vector<char> vchBuf; // the buffer

protected:
    // Read data from the source to fill the buffer
    bool Fill()
    {
        size_t pos = nSrcPos % vchBuf.size();
        size_t readNow = vchBuf.size() - pos;
        size_t nAvail = vchBuf.size() - (nSrcPos - nReadPos) - nRewind;

        if (nAvail < readNow)
            readNow = nAvail;
        if (readNow == 0)
            return false;

        size_t nBytes = fread((void*)&vchBuf[pos], 1, readNow, src);
        if (nBytes == 0) {
            throw std::ios_base::failure(feof(src) ? "CBufferedFile::Fill: end of file"
                                                   : "CBufferedFile::Fill: fread failed");
        }

        nSrcPos += nBytes;
        return true;
    }

public:
    CBufferedFile(FILE* fileIn, uint64_t nBufSize, uint64_t nRewindIn, int nTypeIn, int nVersionIn)
        : nType(nTypeIn), nVersion(nVersionIn), nSrcPos(0), nReadPos(0),
          nReadLimit(static_cast<uint64_t>(-1)), nRewind(nRewindIn), vchBuf(nBufSize, 0)
    {
        if (nRewindIn >= nBufSize)
            throw std::ios_base::failure("CBufferedFile: Rewind limit must be less than buffer size");

        src = fileIn;
    }

    ~CBufferedFile()
    {
        fclose();
    }

    void fclose()
    {
        if (src) {
            ::fclose(src);
            src = nullptr;
        }
    }

    bool eof() const
    {
        return nReadPos == nSrcPos && feof(src);
    }

    void read(char* pch, size_t nSize)
    {
        if (nSize == 0)
            return;

        if (pch == nullptr) {
            throw std::ios_base::failure("CBufferedFile::read(): cannot read from null pointer");
        }

        if (nSize + nReadPos > nReadLimit) {
            throw std::ios_base::failure("CBufferedFile::read(): Read attempted past buffer limit");
        }

        while (nSize > 0) {
            if (nReadPos == nSrcPos)
                Fill();

            size_t pos = nReadPos % vchBuf.size();
            size_t nNow = nSize;

            if (nNow + pos > vchBuf.size())
                nNow = vchBuf.size() - pos;
            if (nNow + nReadPos > nSrcPos)
                nNow = nSrcPos - nReadPos;

            std::copy(&vchBuf[pos], &vchBuf[pos + nNow], pch);

            nReadPos += nNow;
            pch += nNow;
            nSize -= nNow;
        }
    }
};

    // Return the current reading position
    uint64_t GetPos() const
    {
        return nReadPos;
    }

    // Rewind to a given reading position
    bool SetPos(uint64_t nPos)
    {
        size_t bufsize = vchBuf.size();
        if (nPos + bufsize < nSrcPos) {
            // Rewinding too far, rewind as far as possible
            nReadPos = nSrcPos - bufsize;
            return false;
        }
        if (nPos > nSrcPos) {
            // Can't go this far forward, go as far as possible
            nReadPos = nSrcPos;
            return false;
        }
        nReadPos = nPos;
        return true;
    }

    bool Seek(uint64_t nPos)
    {
        long nLongPos = nPos;
        if (nPos != static_cast<uint64_t>(nLongPos)) {
            return false;
        }
        if (fseek(src, nLongPos, SEEK_SET) != 0) {
            return false;
        }
        long nNewPos = ftell(src);
        if (nNewPos < 0) {
            return false;
        }
        nSrcPos = nNewPos;
        nReadPos = nNewPos;
        return true;
    }

    // Prevent reading beyond a certain position
    bool SetLimit(uint64_t nPos = static_cast<uint64_t>(-1))
    {
        if (nPos < nReadPos) {
            return false;
        }
        nReadLimit = nPos;
        return true;
    }

    template <typename T>
    CBufferedFile& operator>>(T& obj)
    {
        // Unserialize from this stream
        ::Unserialize(*this, obj);
        return *this;
    }

    // Search for a given byte in the stream, and remain positioned on it
    void FindByte(char ch)
    {
        while (true) {
            if (nReadPos == nSrcPos)
                Fill();
            if (vchBuf[nReadPos % vchBuf.size()] == ch)
                break;
            nReadPos++;
        }
    }
};
#endif // BITCOIN_STREAMS_H
