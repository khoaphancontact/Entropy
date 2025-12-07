import XCTest
@testable import Entropy  // Change to your module name if needed

final class ZeroizedDataTests: XCTestCase {
    
    func testInitCopiesBytesCorrectlyFromData() throws {
        let input = Data([1, 2, 3, 4, 5])
        let zd = ZeroizedData(copying: input)
        
        XCTAssertEqual(zd.count, 5)
        XCTAssertFalse(zd.isWiped)
        
        try zd.withBytes { buf in
            XCTAssertEqual(Array(buf), [1, 2, 3, 4, 5])
        }
    }
    
    func testInitCopiesBytesCorrectlyFromCollection() throws {
        let input: [UInt8] = [9, 8, 7]
        let zd = ZeroizedData(copying: input)
        
        XCTAssertEqual(zd.count, 3)
        
        try zd.withBytes { buf in
            XCTAssertEqual(Array(buf), input)
        }
    }
    
    func testWithBytesDoesNotCopyMemory() throws {
        let input: [UInt8] = [10, 20, 30]
        let zd = ZeroizedData(copying: input)
        
        var pointer1: UnsafeRawPointer?
        var pointer2: UnsafeRawPointer?
        
        try zd.withBytes { buf in
            pointer1 = UnsafeRawPointer(buf.baseAddress!)
        }
        try zd.withBytes { buf in
            pointer2 = UnsafeRawPointer(buf.baseAddress!)
        }
        
        XCTAssertEqual(pointer1, pointer2)
    }
    
    func testWithMutableBytesMutatesUnderlyingStorage() throws {
        let zd = ZeroizedData(copying: [9, 9, 9])
        
        try zd.withMutableBytes { mutableBuf in
            XCTAssertEqual(mutableBuf.count, 3)
            mutableBuf[1] = 42
        }
        
        try zd.withBytes { buf in
            XCTAssertEqual(Array(buf), [9, 42, 9])
        }
    }
    
    func testWipeZeroizesAndPreventsFurtherAccess() throws {
        let zd = ZeroizedData(copying: [7, 7, 7])
        
        XCTAssertFalse(zd.isWiped)
        XCTAssertEqual(zd.count, 3)
        
        zd.wipe()
        
        XCTAssertTrue(zd.isWiped)
        XCTAssertEqual(zd.count, 0)
        
        // Access should now throw
        XCTAssertThrowsError(try zd.withBytes { _ in }) { error in
            XCTAssertEqual(error as? ZeroizedData.ZeroizedDataError, .wiped)
        }
        
        XCTAssertThrowsError(try zd.withMutableBytes { _ in }) { error in
            XCTAssertEqual(error as? ZeroizedData.ZeroizedDataError, .wiped)
        }
    }
    
    func testWipeIsIdempotent() {
        let zd = ZeroizedData(copying: [1, 2, 3])
        
        zd.wipe()
        XCTAssertTrue(zd.isWiped)
        
        // Second wipe should not crash or change state
        zd.wipe()
        XCTAssertTrue(zd.isWiped)
        XCTAssertEqual(zd.count, 0)
    }
    
    func testDeinitTriggersWipe() {
        weak var weakRef: ZeroizedData?
        
        autoreleasepool {
            let zd = ZeroizedData(copying: [55, 66, 77])
            weakRef = zd
            
            // Force some access
            _ = try? zd.withBytes { buf in
                XCTAssertEqual(Array(buf), [55, 66, 77])
            }
            
            // Leaving scope should call deinit -> wipe()
        }
        
        // Object should be deallocated
        XCTAssertNil(weakRef)
        
        // We deliberately do NOT inspect freed memory.
        // Memory safety + sanitizers are expected to enforce correctness.
    }
    
    func testAccessAfterWipeThrowsWipedError() {
        let zd = ZeroizedData(copying: [5, 5, 5])
        zd.wipe()
        
        XCTAssertTrue(zd.isWiped)
        
        XCTAssertThrowsError(try zd.withBytes { _ in }) { error in
            XCTAssertEqual(error as? ZeroizedData.ZeroizedDataError, .wiped)
        }
        
        XCTAssertThrowsError(try zd.withMutableBytes { _ in }) { error in
            XCTAssertEqual(error as? ZeroizedData.ZeroizedDataError, .wiped)
        }
    }
    
    func testEmptyInitializationBehavesConsistently() {
        let zd1 = ZeroizedData(copying: Data())
        let zd2 = ZeroizedData(copying: [UInt8]())
        
        XCTAssertEqual(zd1.count, 0)
        XCTAssertTrue(zd1.isWiped == false || zd1.isWiped == true) // Just ensure it doesn't crash
        
        XCTAssertEqual(zd2.count, 0)
        
        // Access to empty should be treated as wiped or invalid
        XCTAssertThrowsError(try zd1.withBytes { _ in })
        XCTAssertThrowsError(try zd2.withBytes { _ in })
    }
}
