import ISO_8824
import ISO_8825

extension ISO_8824.ObjectIdentifier {

    public enum X509ExtensionID: Sendable {

        public static let authorityKeyIdentifier: ISO_8824.ObjectIdentifier = [2, 5, 29, 35]

        public static let subjectKeyIdentifier: ISO_8824.ObjectIdentifier = [2, 5, 29, 14]

        public static let keyUsage: ISO_8824.ObjectIdentifier = [2, 5, 29, 15]

        public static let subjectAlternativeName: ISO_8824.ObjectIdentifier = [2, 5, 29, 17]

        public static let basicConstraints: ISO_8824.ObjectIdentifier = [2, 5, 29, 19]

        public static let nameConstraints: ISO_8824.ObjectIdentifier = [2, 5, 29, 30]

        public static let extendedKeyUsage: ISO_8824.ObjectIdentifier = [2, 5, 29, 37]

        public static let authorityInformationAccess: ISO_8824.ObjectIdentifier = [
            1, 3, 6, 1, 5, 5, 7, 1, 1,
        ]
    }
}
