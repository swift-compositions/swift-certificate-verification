import ISO_8824
import ISO_8825
import Time_Primitive

@usableFromInline
enum Time: ISO_8825.DER.Parseable, ISO_8825.DER.Serializable, Hashable, Sendable {
    case utcTime(ISO_8824.UTCTime)
    case generalTime(ISO_8824.GeneralizedTime)

    @inlinable
    init(derEncoded rootNode: ISO_8825.Node) throws(ISO_8824.Error) {
        switch rootNode.identifier {
        case ISO_8824.GeneralizedTime.defaultIdentifier:
            self = .generalTime(try ISO_8824.GeneralizedTime(derEncoded: rootNode))

        case ISO_8824.UTCTime.defaultIdentifier:
            self = .utcTime(try ISO_8824.UTCTime(derEncoded: rootNode))

        default:
            throw ISO_8824.Error.unexpectedFieldType(rootNode.identifier)
        }
    }

    @inlinable
    func serialize(into coder: inout ISO_8825.DER.Serializer) throws(ISO_8824.Error) {
        switch self {
        case .utcTime(let utcTime):
            try coder.serialize(utcTime)

        case .generalTime(let generalizedTime):
            try coder.serialize(generalizedTime)
        }
    }

    @inlinable
    static func makeTime(from instant: Instant) throws(ISO_8824.Error) -> Time {
        let components = instant.utcDate

        guard ((1950)..<(2050)).contains(components.year) else {
            let generalizedTime = try ISO_8824.GeneralizedTime(components)
            return .generalTime(generalizedTime)
        }
        let utcTime = try ISO_8824.UTCTime(components)
        return .utcTime(utcTime)
    }
}

extension Instant {
    @inlinable
    package init(
        fromUTCDate date: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int)
    ) {
        self.init(secondsSinceUnixEpoch: Int64(timestampFromUTCDate: date))
    }

    @inlinable
    package var utcDate: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int) {

        self.secondsSinceUnixEpoch.utcDateFromTimestamp
    }

    @inlinable
    init(_ time: Time) {
        switch time {
        case .generalTime(let generalizedTime):
            self = .init(generalizedTime)

        case .utcTime(let utcTime):
            self = .init(utcTime)
        }
    }

    @inlinable
    package init(_ time: ISO_8824.GeneralizedTime) {
        self = Instant(
            fromUTCDate: (
                year: time.year, month: time.month, day: time.day, hours: time.hours,
                minutes: time.minutes,
                seconds: time.seconds
            )
        )
    }

    @inlinable
    package init(_ time: ISO_8824.UTCTime) {
        self = Instant(
            fromUTCDate: (
                year: time.year, month: time.month, day: time.day, hours: time.hours,
                minutes: time.minutes,
                seconds: time.seconds
            )
        )
    }
}

extension ISO_8824.GeneralizedTime {
    @inlinable
    init(_ time: Time) {
        switch time {
        case .generalTime(let t):
            self = t

        case .utcTime(let t):

            self = try! ISO_8824.GeneralizedTime(
                year: t.year,
                month: t.month,
                day: t.day,
                hours: t.hours,
                minutes: t.minutes,
                seconds: t.seconds,
                fractionalSeconds: 0
            )
        }
    }

    @inlinable
    package init(
        _ components: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int)
    ) throws(ISO_8824.Error) {
        try self.init(
            year: components.year,
            month: components.month,
            day: components.day,
            hours: components.hours,
            minutes: components.minutes,
            seconds: components.seconds,
            fractionalSeconds: 0.0
        )
    }

    @inlinable
    package init(_ instant: Instant) {

        try! self.init(instant.utcDate)
    }
}

extension ISO_8824.UTCTime {
    @inlinable
    package init(
        _ components: (year: Int, month: Int, day: Int, hours: Int, minutes: Int, seconds: Int)
    ) throws(ISO_8824.Error) {
        try self.init(
            year: components.year,
            month: components.month,
            day: components.day,
            hours: components.hours,
            minutes: components.minutes,
            seconds: components.seconds
        )
    }
}
