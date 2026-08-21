#if compiler(>=6.2)
    public typealias _X509SendableMetatype = SendableMetatype
#else
    public typealias _X509SendableMetatype = Any
#endif
