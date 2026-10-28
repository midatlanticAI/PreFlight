// ProfileStore.swift
// Restores user objects with the NSSecureCoding-checked API, so only the
// classes named here can be instantiated from the bytes.

import Foundation

final class ProfileStore {
    func restoreProfile(from data: Data) throws -> UserProfile? {
        return try NSKeyedUnarchiver.unarchivedObject(ofClass: UserProfile.self, from: data)
    }

    func restoreGraph(_ data: Data) throws -> Any? {
        return try NSKeyedUnarchiver.unarchivedObject(
            ofClasses: [NSArray.self, NSDictionary.self, NSString.self, NSNumber.self],
            from: data
        )
    }

    func decodeSessionState(_ data: Data) -> SessionState? {
        let unarchiver = NSKeyedUnarchiver(forReadingWith: data)
        unarchiver.requiresSecureCoding = true
        defer { unarchiver.finishDecoding() }
        return unarchiver.decodeObject(of: SessionState.self, forKey: "state")
    }
}
