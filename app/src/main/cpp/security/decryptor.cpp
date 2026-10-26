// app/src/main/cpp/engine/decryptor.cpp
#include <vector>
#include <cstdint>

namespace shield::engine {

void transformPayload(std::vector<uint8_t>& buffer, uint32_t seedKey) {
    uint32_t state = seedKey;
    for (size_t i = 0; i < buffer.size(); ++i) {
        // Xorshift32 keystream
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        buffer[i] ^= static_cast<uint8_t>((state & 0xFF) ^ (i & 0xFF));
    }
}

} // namespace shield::engine
