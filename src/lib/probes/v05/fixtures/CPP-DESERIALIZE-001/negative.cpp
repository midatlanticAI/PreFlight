// settings_cache.cpp
// Round-trips the app's own settings cache through a local file. Nothing
// in this translation unit reads from the network, so the archive input
// is bytes this process wrote itself.

#include <fstream>

#include <cereal/archives/binary.hpp>

#include "settings.hpp"

static const char* kCachePath = "cache/settings.bin";

Settings loadSettings() {
    std::ifstream stream(kCachePath, std::ios::binary);
    Settings settings;
    if (stream) {
        cereal::BinaryInputArchive archive(stream);
        archive(settings);
    }
    return settings;
}

void saveSettings(const Settings& settings) {
    std::ofstream stream(kCachePath, std::ios::binary);
    cereal::BinaryOutputArchive archive(stream);
    archive(settings);
}
