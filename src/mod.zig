const std = @import("std");
const meta = std.meta;
const base64 = std.base64;

const Allocator = std.mem.Allocator;
const Decoder = std.base64.standard.Decoder;

const debug = std.debug.print;
const assert = std.debug.assert;
const memcmp = std.mem.eql;

pub const Error = error{
    InvalidFileFormat,
    InvalidMagicString,
    /// Invalid RFC-4251 integer
    MalformedInteger,
    /// Invalid RFC-4251 string
    MalformedString,
    /// As per spec, repeated extension are not allowed.
    RepeatedExtension,
    UnkownExtension,
} || std.base64.Error || Allocator.Error;

fn GenericIteratorInner(comptime T: type, parse_value: anytype) type {
    return struct {
        ref: []const u8,
        off: usize,

        const Self = @This();

        pub fn next(self: *Self) T {
            if (self.done()) return null;

            const off, const ret = parse_string(self.ref[self.off..]) catch
                return null;

            self.off += off;

            return parse_value(self.ref, &self.off, ret);
        }

        pub fn reset(self: *Self) void {
            self.off = 0;
        }

        pub fn done(self: *const Self) bool {
            return self.off == self.ref.len;
        }
    };
}

fn GenericIterator(comptime parse_value: anytype) type {
    const T = switch (@typeInfo(@TypeOf(parse_value))) {
        .Fn => |func| func.return_type.?,
        else => @compileError("Expected fn"),
    };

    return GenericIteratorInner(T, parse_value);
}

fn enum_to_ssh_str(comptime T: type, sufix: []const u8) [meta.fields(T).len][]const u8 {
    if (@typeInfo(T) != .Enum)
        @compileError("Expected enum");

    const fields = meta.fields(T);

    comptime var ret: [fields.len][]const u8 = undefined;

    inline for (fields, &ret) |field, *r| {
        const U = [field.name.len]u8;

        comptime var name: U = std.mem.zeroes(U);

        inline for (field.name, &name) |c, *n| {
            n.* = if (c == '_') '-' else c;
        }

        r.* = name ++ sufix;
    }

    return ret;
}

const Pem = struct {
    allocator: Allocator,
    decoder: base64.Base64Decoder,

    pem: ?struct {
        magic: Magic,
        // FIXME: Implement support for this
        comment: ?[]const u8 = null,
        ref: []const u8,
        host: []const u8,
        // Certificate in DER
    },

    der: ?[]u8 = null,

    const Self = @This();

    pub fn init(allocator: Allocator, decoder: base64.Base64Decoder) Self {
        return .{
            .allocator = allocator,
            .decoder = decoder,
            .pem = .{
                .magic = undefined,
                .ref = undefined,
                .host = undefined,
            },
        };
    }

    pub fn from_bytes(self: *Self, buf: []const u8) Error!void {
        var it = std.mem.tokenizeAny(u8, buf, " ");

        const magic = parse_magic(it.next() orelse return Error.InvalidFileFormat) orelse
            return Error.InvalidMagicString;

        const ref = it.next() orelse return Error.InvalidFileFormat;

        const host = it.next() orelse return Error.InvalidFileFormat;

        const len = try self.decoder.calcSizeForSlice(ref);

        self.der = try self.allocator.alloc(u8, len);
        errdefer self.deinit();

        try self.decoder.decode(self.der.?, ref);

        self.pem = .{
            .magic = magic,
            .ref = ref,
            .host = host,
        };
    }

    pub fn reset(self: *Self) void {
        self.pem = null;

        self.deinit();
    }

    pub fn deinit(self: *Self) void {
        if (self.der) |der|
            self.allocator.free(der);
    }
};

pub const Cert = union(enum) {
    rsa: RSA,
    // dsa: DSA,
    ecdsa: ECDSA,
    ed25519: ED25519,

    const Self = @This();

    pub fn from_der(magic: ?Magic, der: []const u8) Error!Self {
        // FIXME: get the magic
        const m = magic orelse
            return Error.InvalidMagicString;

        return switch (m) {
            .ssh_rsa,
            .rsa_sha2_256,
            .rsa_sha2_512,
            => .{ .rsa = try RSA.from_bytes(m, der) },

            // .ssh_dsa,
            // => .{ .dsa = try DSA.from(der, m) },

            .ecdsa_sha2_nistp256,
            .ecdsa_sha2_nistp384,
            .ecdsa_sha2_nistp521,
            => .{ .ecdsa = try ECDSA.from_bytes(m, der) },

            .ssh_ed25519,
            => .{ .ed25519 = try ED25519.from_bytes(m, der) },

            else => std.debug.panic("DSA certificates are not supported for now", .{}),
        };
    }
};

pub const Magic = enum(u3) {
    ssh_rsa,
    ssh_dsa,
    ecdsa_sha2_nistp256,
    ecdsa_sha2_nistp384,
    ecdsa_sha2_nistp521,
    ssh_ed25519,
    rsa_sha2_256,
    rsa_sha2_512,

    const Self = @This();

    const strings = enum_to_ssh_str(Magic, "-cert-v01@openssh.com");

    fn as_string(self: *const Self) []const u8 {
        return strings[@intFromEnum(self.*)];
    }
};

pub const CertType = enum(u2) {
    user = 1,
    host = 2,
};

/// The critical options section of the certificate specifies zero or more
/// options on the certificate's validity.
pub const CriticalOptions = struct {
    ref: []const u8 = undefined,

    const Self = @This();

    pub const Tags = enum {
        /// Specifies a command that is executed (replacing any the user specified
        /// on the ssh command-line) whenever this key is used for authentication.
        force_command,

        /// Comma-separated list of source addresses from which this certificate is
        /// accepted for authentication. Addresses are specified in CIDR format
        /// (nn.nn.nn.nn/nn or hhhh::hhhh/nn). If this option is not present, then
        /// certificates may be presented from any source address.
        source_address,

        /// Flag indicating that signatures made with this certificate must assert
        /// FIDO user verification (e.g. PIN or biometric). This option only makes
        /// sense for the U2F/FIDO security key types that support this feature in
        /// their signature formats.
        verify_required,

        pub const strings = enum_to_ssh_str(Self.Tags, "");

        pub fn as_string(self: *const Self.Tags) []const u8 {
            return Self.Tag.strings[self.*];
        }
    };

    pub fn iter(self: *const Self) Self.Iterator {
        return .{ .ref = self.ref, .off = 0 };
    }

    pub const Iterator = GenericIterator(
        struct {
            // FIXME: Should return an error
            inline fn parse_value(ref: []const u8, off: *usize, key: []const u8) ?CriticalOption {
                const opt = Self.is_valid_option(key) orelse
                    return null;

                const next, const buf = parse_string(ref[off.*..]) catch
                    return null;

                _, const value = parse_string(buf) catch
                    return null;

                off.* += next;

                return .{ .kind = opt, .value = value };
            }
        }.parse_value,
    );

    inline fn is_valid_option(opt: []const u8) ?CriticalOptions.Tags {
        for (Self.Tags.strings, 0..) |s, i| {
            if (memcmp(u8, s, opt)) return @enumFromInt(i);
        }

        return null;
    }
};

pub const CriticalOption = struct {
    kind: CriticalOptions.Tags,
    value: []const u8,
};

/// The extensions section of the certificate specifies zero or more
/// non-critical certificate extensions.
pub const Extensions = struct {
    ref: []const u8 = undefined,

    const Self = @This();

    pub const Tags = enum(u8) {
        /// Flag indicating that signatures made with this certificate need not
        /// assert FIDO user presence. This option only makes sense for the
        /// U2F/FIDO security key types that support this feature in their
        /// signature formats.
        no_touch_required = 0x01 << 0,

        /// Flag indicating that X11 forwarding should be permitted. X11 forwarding
        /// will be refused if this option is absent.
        permit_X11_forwarding = 0x01 << 1,

        /// Flag indicating that agent forwarding should be allowed. Agent
        /// forwarding must not be permitted unless this option is present.
        permit_agent_forwarding = 0x01 << 2,

        /// Flag indicating that port-forwarding should be allowed. If this option
        /// is not present, then no port forwarding will be allowed.
        permit_port_forwarding = 0x01 << 3,

        /// Flag indicating that PTY allocation should be permitted. In the absence
        /// of this option PTY allocation will be disabled.
        permit_pty = 0x01 << 4,

        /// Flag indicating that execution of ~/.ssh/rc should be permitted.
        /// Execution of this script will not be permitted if this option is not
        /// present.
        permit_user_rc = 0x01 << 5,

        const strings = enum_to_ssh_str(Self.Tags, "");

        pub inline fn as_string(self: *const Self.Tags) []const u8 {
            return Self.strings[@intFromEnum(self.*)];
        }
    };

    pub fn iter(self: *const Self) Self.Iterator {
        return .{ .ref = self.ref, .off = 0 };
    }

    pub const Iterator = GenericIterator(
        struct {
            inline fn parse_value(ref: []const u8, off: *usize, key: []const u8) ?[]const u8 {
                // Skip empty pair
                if (ref.len != off.*) off.* += @sizeOf(u32);

                return key;
            }
        }.parse_value,
    );

    /// Returns the extensions as bitflags, checking if they are valid.
    pub fn to_bitflags(self: *const Self) Error!u8 {
        var ret: u8 = 0;

        var it = self.iter();

        outer: while (it.next()) |ext| {
            for (Self.Tags.strings, 0..) |ext_str, j| {
                if (memcmp(u8, ext, ext_str)) {
                    const bit: u8 = (@as(u8, 0x01) << @as(u3, @intCast(j)));

                    if (ret & bit != 0)
                        return Error.RepeatedExtension;

                    ret |= bit;

                    continue :outer;
                }
            }

            return Error.UnkownExtension;
        }

        return ret;
    }
};

const Principals = struct {
    ref: []const u8,

    const Self = @This();

    fn iter(self: *const Self) Self.Iterator {
        return .{ .ref = self.ref, .off = 0 };
    }

    pub const Iterator = GenericIterator(
        struct {
            inline fn parse_value(_: []const u8, _: *usize, key: []const u8) ?[]const u8 {
                return key;
            }
        }.parse_value,
    );
};

pub const RSA = struct {
    magic: Magic,
    nonce: []const u8,
    e: []const u8, // TODO: mpint
    n: []const u8, // TODO: mpint
    serial: u64,
    kind: CertType,
    key_id: []const u8,
    valid_principals: Principals,
    valid_after: u64,
    valid_before: u64,
    critical_options: CriticalOptions,
    extensions: Extensions,
    reserved: []const u8,
    signature_key: []const u8,
    signature: []const u8,

    const Self = @This();

    fn from_bytes(magic: Magic, der: []const u8) !RSA {
        return try parse(Self, magic, der);
    }
};

// NOT USED
// pub const DSA = struct {
//     magic: Magic,
//     nonce: []const u8,
//     p: []const u8, // TODO: mpint
//     q: []const u8, // TODO: mpint
//     g: []const u8, // TODO: mpint
//     y: []const u8, // TODO: mpint
//     serial: u64,
//     kind: CertType,
//     key_id: []const u8,
//     valid_principals: Principals,
//     valid_after: []const u8,
//     valid_before: []const u8,
//     critical_options: CriticalOptions,
//     extensions: Extensions,
//     reserved: []const u8,
//     signature_key: []const u8,
//     signature: []const u8,
// };

pub const ECDSA = struct {
    magic: Magic,
    nonce: []const u8,
    curve: []const u8,
    public_key: []const u8,
    serial: u64,
    kind: CertType,
    key_id: []const u8,
    valid_principals: Principals,
    valid_after: u64,
    valid_before: u64,
    critical_options: CriticalOptions,
    extensions: Extensions,
    reserved: []const u8,
    signature_key: []const u8,
    signature: []const u8,

    const Self = @This();

    fn from_bytes(magic: Magic, buf: []const u8) !ECDSA {
        return try parse(Self, magic, buf);
    }
};

pub const ED25519 = struct {
    magic: Magic,
    nonce: []const u8,
    pk: []const u8,
    serial: u64,
    kind: CertType,
    key_id: []const u8,
    valid_principals: Principals,
    valid_after: u64,
    valid_before: u64,
    critical_options: []const u8,
    extensions: []const u8,
    reserved: []const u8,
    signature_key: []const u8,
    signature: []const u8,

    const Self = @This();

    fn from_bytes(magic: Magic, buf: []const u8) !ED25519 {
        return try parse(Self, magic, buf);
    }
};

inline fn read_int(comptime T: type, buf: []const u8) ?T {
    if (buf.len < @sizeOf(T))
        return null;

    return std.mem.readInt(T, buf[0..@sizeOf(T)], std.builtin.Endian.big);
}

inline fn parse_int(comptime T: type, buf: []const u8) Error!struct { usize, T } {
    if (read_int(T, buf)) |n|
        return .{ @sizeOf(T), n };

    return Error.MalformedInteger;
}

inline fn parse_string(buf: []const u8) Error!struct { usize, []const u8 } {
    if (read_int(u32, buf)) |len| {
        const size = len + @sizeOf(u32);

        if (size > buf.len)
            return Error.MalformedString;

        return .{ size, buf[@sizeOf(u32)..size] };
    }

    return Error.MalformedString;
}

inline fn parse_magic(ref: []const u8) ?Magic {
    for (Magic.strings, 0..) |magic, i| {
        if (memcmp(u8, magic, ref))
            return @enumFromInt(i);
    }

    return null;
}

fn Cont(comptime T: type) type {
    return struct {
        usize,
        T,
    };
}

inline fn parse_cert_type(ref: []const u8) Error!Cont(CertType) {
    const next, const val = try parse_int(u32, ref);

    return .{ next, @enumFromInt(val) };
}

inline fn parse_critical_options(buf: []const u8) Error!Cont(CriticalOptions) {
    const next, const ref = try parse_string(buf);

    return .{ next, .{ .ref = ref } };
}

inline fn parse_principals(buf: []const u8) Error!Cont(Principals) {
    const next, const ref = try parse_string(buf);

    return .{ next, .{ .ref = ref } };
}

inline fn parse_extensions(buf: []const u8) Error!Cont(Extensions) {
    const next, const ref = try parse_string(buf);

    return .{ next, .{ .ref = ref } };
}

inline fn parse(comptime T: type, magic: Magic, buf: []const u8) Error!T {
    var ret: T = undefined;

    ret.magic = magic;

    var i: usize = Magic.strings[@intFromEnum(magic)].len + @sizeOf(u32);

    inline for (meta.fields(T)) |f| {
        const ref = buf[i..];

        const next, const val = switch (f.type) {
            // RFC-4251 string
            []const u8 => try parse_string(ref),

            // RFC-4251 uint64
            u64 => try parse_int(u64, ref),

            // RFC-4251 uint32
            CertType => try parse_cert_type(ref),

            // RFC-4251 string
            CriticalOptions => try parse_critical_options(ref),

            // RFC-4251 string
            Principals => try parse_principals(ref),

            // RFC-4251 string
            Extensions => try parse_extensions(ref),

            // Don't unroll anything else
            else => continue,
        };

        i += next;

        @field(ret, f.name) = val;
    }

    return ret;
}

const Timer = std.time.Timer;

const expectEqual = std.testing.expectEqual;
const expect = std.testing.expect;

const testing = std.testing;

test "parse rsa cert" {
    var pem = Pem.init(testing.allocator, Decoder);
    defer pem.deinit();

    try pem.from_bytes(@embedFile("test/rsa-cert.pub"));

    switch (try Cert.from_der(
        pem.pem.?.magic,
        pem.der.?,
    )) {
        .rsa => |cert| {
            try expectEqual(cert.magic, Magic.ssh_rsa);
            try expectEqual(cert.serial, 2);
            try expectEqual(cert.kind, CertType.user);
            try expect(memcmp(u8, cert.key_id, "abc"));

            var it = cert.valid_principals.iter();
            try expect(memcmp(u8, it.next().?, "root"));
            try expect(it.done());

            try expectEqual(cert.valid_after, 0);
            try expectEqual(cert.valid_before, std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "parse ecdsa cert" {
    var pem = Pem.init(testing.allocator, Decoder);
    defer pem.deinit();

    try pem.from_bytes(@embedFile("test/ecdsa-cert.pub"));

    switch (try Cert.from_der(
        pem.pem.?.magic,
        pem.der.?,
    )) {
        .ecdsa => |cert| {
            try expectEqual(cert.magic, Magic.ecdsa_sha2_nistp256);
            try expectEqual(cert.serial, 2);
            try expectEqual(cert.kind, CertType.user);
            try expect(memcmp(u8, cert.key_id, "abc"));

            var it = cert.valid_principals.iter();
            try expect(memcmp(u8, it.next().?, "root"));
            try expect(it.done());

            try expectEqual(cert.valid_after, 0);
            try expectEqual(cert.valid_before, std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "parse ed25519 cert" {
    var pem = Pem.init(testing.allocator, Decoder);
    defer pem.deinit();

    try pem.from_bytes(@embedFile("test/ed25519-cert.pub"));

    switch (try Cert.from_der(
        pem.pem.?.magic,
        pem.der.?,
    )) {
        .ed25519 => |cert| {
            try expectEqual(cert.magic, Magic.ssh_ed25519);
            try expectEqual(cert.serial, 2);
            try expectEqual(cert.kind, CertType.user);

            try expect(memcmp(u8, cert.key_id, "abc"));

            var it = cert.valid_principals.iter();
            try expect(memcmp(u8, it.next().?, "root"));
            try expect(it.done());

            try expectEqual(cert.valid_after, 0);
            try expectEqual(cert.valid_before, std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "benchmark rsa `from_bytes`" {
    var pem = Pem.init(testing.allocator, Decoder);
    defer pem.deinit();

    try pem.from_bytes(@embedFile("test/rsa-cert.pub"));

    var timer = try Timer.start();

    var sum: u64 = 0;
    for (0..1024) |_| {
        _ = try RSA.from_bytes(pem.pem.?.magic, pem.der.?);

        sum += timer.lap();
    }

    debug("rsa `from_bytes` took ~= {}ns\n", .{sum / 1024});
}

test "extensions iterator" {
    var pem = Pem.init(testing.allocator, Decoder);
    defer pem.deinit();

    const extensions = [_][]const u8{
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-pty",
        "permit-user-rc",
    };

    try pem.from_bytes(@embedFile("test/rsa-cert.pub"));

    const rsa = try RSA.from_bytes(pem.pem.?.magic, pem.der.?);

    var it = rsa.extensions.iter();

    for (extensions) |extension| {
        try expect(memcmp(u8, extension, it.next().?));
    }

    try expect(it.done());
}

test "extensions to bitflags" {
    const Ext = Extensions.Tags;

    var pem = Pem.init(testing.allocator, Decoder);
    defer pem.deinit();

    try pem.from_bytes(@embedFile("test/rsa-cert.pub"));

    const rsa = try RSA.from_bytes(pem.pem.?.magic, pem.der.?);

    try expectEqual(
        try rsa.extensions.to_bitflags(),
        @intFromEnum(Ext.permit_agent_forwarding) |
            @intFromEnum(Ext.permit_X11_forwarding) |
            @intFromEnum(Ext.permit_user_rc) |
            @intFromEnum(Ext.permit_port_forwarding) |
            @intFromEnum(Ext.permit_pty),
    );
}

test "multiple valid principals iterator" {
    // Reference
    const valid_principals = [_][]const u8{
        "foo",
        "bar",
        "baz",
    };

    var pem = Pem.init(testing.allocator, Decoder);
    defer pem.deinit();

    try pem.from_bytes(@embedFile("test/multiple-principals-cert.pub"));

    const rsa = try RSA.from_bytes(pem.pem.?.magic, pem.der.?);

    var it = rsa.valid_principals.iter();

    for (valid_principals) |principal| {
        try expect(memcmp(u8, principal, it.next().?));
    }
}

test "critical options iterator" {
    // Reference
    const critical_options = [_]CriticalOption{.{
        .kind = .force_command,
        .value = "ls -la",
    }};

    var pem = Pem.init(testing.allocator, Decoder);
    defer pem.deinit();

    try pem.from_bytes(@embedFile("test/force-command-cert.pub"));

    const rsa = try RSA.from_bytes(pem.pem.?.magic, pem.der.?);

    var it = rsa.critical_options.iter();

    for (critical_options) |critical_option| {
        const opt = it.next().?;

        try expectEqual(critical_option.kind, opt.kind);
        try expect(memcmp(u8, critical_option.value, opt.value));
    }

    try expect(it.done());
}

test "multiple critical options iterator" {
    // Reference
    const critical_options = [_]CriticalOption{
        .{
            .kind = .force_command,
            .value = "ls -la",
        },
        .{
            .kind = .source_address,
            .value = "198.51.100.0/24,203.0.113.0/26",
        },
    };

    var pem = Pem.init(testing.allocator, Decoder);
    defer pem.deinit();

    try pem.from_bytes(@embedFile("test/multiple-critical-options-cert.pub"));

    const rsa = try RSA.from_bytes(pem.pem.?.magic, pem.der.?);

    var it = rsa.critical_options.iter();

    for (critical_options) |critical_option| {
        const opt = it.next().?;

        try expectEqual(critical_option.kind, opt.kind);
        try expect(memcmp(u8, critical_option.value, opt.value));
    }

    try expect(it.done());
}
