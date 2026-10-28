// session_server.cpp
// Rebuilds client session objects from the bytes each client sends on
// connect.

#include <sys/socket.h>

#include <sstream>
#include <string>

#include <cereal/archives/binary.hpp>
#include <boost/archive/binary_iarchive.hpp>

#include "http_request.hpp"
#include "player_profile.hpp"
#include "session_state.hpp"

SessionState readSessionFromSocket(int clientFd) {
    char frame[65536];
    ssize_t got = recv(clientFd, frame, sizeof(frame), 0);
    std::string payload(frame, got > 0 ? static_cast<size_t>(got) : 0);
    std::istringstream stream(payload);

    SessionState state;
    cereal::BinaryInputArchive archive(stream);
    archive(state);
    return state;
}

PlayerProfile readProfileFromRequest(const HttpRequest& request) {
    std::istringstream stream(request.body);
    boost::archive::binary_iarchive input(stream);
    PlayerProfile profile;
    input >> profile;
    return profile;
}
