#pragma once
#include <cstddef>
#include <string>

namespace shield {

template <std::size_t N, char Key>
class ObfuscatedString {
private:
    char m_data[N];

public:
    constexpr ObfuscatedString(const char (&str)[N]) : m_data{} {
        for (std::size_t i = 0; i < N; ++i) {
            m_data[i] = str[i] ^ (Key + static_cast<char>(i * 13));
        }
    }

    inline std::string decrypt() const {
        std::string result(N - 1, '\0');
        for (std::size_t i = 0; i < N - 1; ++i) {
            result[i] = m_data[i] ^ (Key + static_cast<char>(i * 13));
        }
        return result;
    }
};

} // namespace shield

#define OBFS_STR(str) \
    ([]() -> std::string { \
        constexpr shield::ObfuscatedString<sizeof(str), 0x5A> obfs(str); \
        return obfs.decrypt(); \
    }())
