// ProfileStore.swift
// Restores user objects from Data blobs the sync service sends down.

import Foundation

final class ProfileStore {
    private let defaults = UserDefaults.standard

    func restoreProfile(from data: Data) -> UserProfile? {
        // Legacy unarchive of bytes that came off the wire.
        let object = NSKeyedUnarchiver.unarchiveObject(with: data)
        return object as? UserProfile
    }

    func restoreSettings(_ data: Data) throws -> AppSettings? {
        let object = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data)
        return object as? AppSettings
    }

    func decodeSessionState(_ data: Data) -> SessionState? {
        let unarchiver = NSKeyedUnarchiver(forReadingWith: data)
        defer { unarchiver.finishDecoding() }
        return unarchiver.decodeObject(forKey: "state") as? SessionState
    }

    func loadSharedProfile(at path: String) -> UserProfile? {
        return NSKeyedUnarchiver.unarchiveObject(withFile: path) as? UserProfile
    }
}
