import Testing
import Time_Primitive

@Suite struct `Instant Test Seconds` {}

extension `Instant Test Seconds` {
    static let epoch = Instant(secondsSinceUnixEpoch: 1_767_225_600)

    @Test func `whole seconds advance the second and leave the fraction alone`() {
        let result = Self.epoch + 3.0
        #expect(result.secondsSinceUnixEpoch == 1_767_225_603)
        #expect(result.nanosecondFraction == 0)
    }

    @Test func `a fractional offset lands in the nanosecond part`() {
        let result = Self.epoch + 2.5
        #expect(result.secondsSinceUnixEpoch == 1_767_225_602)
        #expect(result.nanosecondFraction == 500_000_000)
    }

    @Test func `accumulated fractions carry into the next second`() {
        let result = Self.epoch + 0.6 + 0.6
        #expect(result.secondsSinceUnixEpoch == 1_767_225_601)
        #expect(result.nanosecondFraction == 200_000_000)
    }

    @Test func `negative offsets borrow rather than produce an invalid instant`() {
        let result = Self.epoch + -0.25
        #expect(result.secondsSinceUnixEpoch == 1_767_225_599)
        #expect(result.nanosecondFraction == 750_000_000)
        #expect(result.nanosecondFraction >= 0)
        #expect(result.nanosecondFraction < 1_000_000_000)
    }

    @Test func `whole negative offsets subtract exactly`() {
        let result = Self.epoch + -3.0
        #expect(result.secondsSinceUnixEpoch == 1_767_225_597)
        #expect(result.nanosecondFraction == 0)
    }

    @Test func `large offsets stay exact`() {
        let oneYear = 365.0 * 24 * 60 * 60
        let result = Self.epoch + oneYear
        #expect(result.secondsSinceUnixEpoch == 1_767_225_600 + 31_536_000)
        #expect(result.nanosecondFraction == 0)

        let decade = 3650.0 * 24 * 60 * 60
        #expect((Self.epoch + decade).secondsSinceUnixEpoch == 1_767_225_600 + 315_360_000)
    }

    @Test func `offsets preserve ordering`() {
        #expect(Self.epoch < Self.epoch + 1.0)
        #expect(Self.epoch + 2.0 < Self.epoch + 2.5)
        #expect(Self.epoch + 2.5 < Self.epoch + 3.0)
        #expect(Self.epoch + -1.0 < Self.epoch)
    }
}
