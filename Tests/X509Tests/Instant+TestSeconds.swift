import Time_Primitive

extension Instant {

    static func + (lhs: Instant, rhs: Double) -> Instant {
        let wholeSeconds = rhs.rounded(.towardZero)
        let fraction = rhs - wholeSeconds

        let carriedNanoseconds =
            Int64(lhs.nanosecondFraction) + Int64((fraction * 1_000_000_000).rounded())

        var seconds =
            lhs.secondsSinceUnixEpoch + Int64(wholeSeconds)
            + carriedNanoseconds / 1_000_000_000
        var nanoseconds = carriedNanoseconds % 1_000_000_000

        if nanoseconds < 0 {
            nanoseconds += 1_000_000_000
            seconds -= 1
        }

        return Instant(
            _unchecked: (),
            secondsSinceUnixEpoch: seconds,
            nanosecondFraction: Int32(nanoseconds)
        )
    }
}
