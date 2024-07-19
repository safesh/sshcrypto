const std = @import("std");
const meta = std.meta;

const Decoder = std.base64.standard.Decoder;

const debug = std.debug.print;
const assert = std.debug.assert;
const memcmp = std.mem.eql;

pub const Error = error{
    fail_to_parse,
    invalid_magic_string,
    malformed_certificate,
    malformed_integer,
    malformed_string,
    /// As per spec, repeated extension are not allowed.
    repeated_extension,
    unkown_extension,
};

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

fn GenericIterator(
    comptime parse_value: anytype,
) type {
    const T = switch (@typeInfo(@TypeOf(parse_value))) {
        .Fn => |func| func.return_type.?,
        else => @compileError("Expected Fn"),
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

// TODO: Refactor this
pub const Cert = struct {
    allocator: std.mem.Allocator,

    buf: ?[]u8 = null,

    kind: KeyType = undefined,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Cert {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.*.buf) |buf|
            self.allocator.free(buf[0..buf.len]);
    }

    fn get_der(self: *Self, raw: []const u8) ?[]const u8 {
        var it = std.mem.split(u8, raw, " ");

        _ = it.next(); // skip magic if DER encoded

        if (it.next()) |data| {
            const len = Decoder.calcSizeForSlice(data) catch return null;

            self.*.buf = self.allocator.alloc(u8, len) catch return null;

            Decoder.decode(self.*.buf.?, data) catch return null;

            return self.*.buf;
        }

        return null;
    }

    pub fn parse(self: *Self, raw: []const u8) Error!void {
        for (Magic.strings, 0..) |magic, i| {
            if (raw.len < magic.len) return error.malformed_certificate;

            if (memcmp(u8, raw[0..magic.len], magic)) return switch (i) {
                0, 6, 7 => {
                    const data = if (self.get_der(raw)) |der| der else raw;

                    self.kind = .{
                        .rsa = try RSA.from(data, @enumFromInt(i)),
                    };
                },
                1 => {
                    const data = if (self.get_der(raw)) |der| der else raw;

                    self.kind = .{
                        .dsa = try DSA.from(data, @enumFromInt(i)),
                    };
                },
                2...4 => {
                    const data = if (self.get_der(raw)) |der| der else raw;

                    self.kind = .{
                        .ecdsa = try ECDSA.from(data, @enumFromInt(i)),
                    };
                },
                5 => {
                    const data = if (self.get_der(raw)) |der| der else raw;

                    self.kind = .{
                        .ed25519 = try ED25519.from(data, @enumFromInt(i)),
                    };
                },
                else => unreachable,
            };
        }

        // Try to parse pem

        return Error.invalid_magic_string;
    }
};

pub const KeyType = union(enum) {
    rsa: RSA,
    dsa: DSA,
    ecdsa: ECDSA,
    ed25519: ED25519,
};

pub const Magic = enum(u3) {
    ssh_rsa = 0,
    ssh_dss = 1,
    ecdsa_sha2_nistp256 = 2,
    ecdsa_sha2_nistp384 = 3,
    ecdsa_sha2_nistp521 = 4,
    ssh_ed25519 = 5,
    rsa_sha2_256 = 6,
    rsa_sha2_512 = 7,

    const Self = @This();

    const strings = enum_to_ssh_str(Magic, "-cert-v01@openssh.com");

    fn as_string(self: *const Self) []const u8 {
        return strings[@intFromEnum(self.*)];
    }
};

pub const CertType = enum(u32) {
    user = 1,
    host = 2,
};

/// The critical options section of the certificate specifies zero or more
/// options on the certificate's validity.
pub const CriticalOptions = struct {
    ref: []const u8 = undefined,

    const Tag = enum {
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

        pub const strings = enum_to_ssh_str(Self.Tag, "");
    };

    const Self = @This();

    pub fn as_string(self: *const Self) []const u8 {
        return Self.Tag.strings[self.*];
    }

    pub fn iter(self: *Self) Self.Iterator {
        return Self.Iterator{
            .ref = self.ref,
            .off = 0,
        };
    }

    pub const Iterator = GenericIterator(
        struct {
            // FIXME: Should return an error
            inline fn parse_value(ref: []const u8, off: *usize, key: []const u8) ?CriticalOption {
                const opt = Self.is_option(key) orelse
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

    inline fn is_option(opt: []const u8) ?CriticalOptions.Tag {
        for (Self.Tag.strings, 0..) |s, i| {
            if (memcmp(u8, s, opt)) return @enumFromInt(i);
        }

        return null;
    }
};

pub const CriticalOption = struct {
    kind: CriticalOptions.Tag,
    value: []const u8,
};

/// The extensions section of the certificate specifies zero or more
/// non-critical certificate extensions.
pub const Extensions = struct {
    ref: []const u8 = undefined,

    const Tags = enum(u8) {
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
    };

    const Self = @This();

    fn iter(self: Self) Self.Iterator {
        return .{
            .ref = self.ref,
            .off = 0,
        };
    }

    const Iterator = GenericIterator(
        struct {
            inline fn parse_value(ref: []const u8, off: *usize, key: []const u8) ?[]const u8 {
                // Skip empty pair
                if (ref.len != off.*) off.* += @sizeOf(u32);

                return key;
            }
        }.parse_value,
    );

    inline fn as_string(self: *const Self) []const u8 {
        return Self.strings[@intFromEnum(self.*)];
    }

    /// Returns the extensions as bitflags, checking if they are valid.
    fn to_bitflags(self: *Self) Error!u8 {
        var ret: u8 = 0;

        var it = self.iter();

        outer: while (it.next()) |ext| {
            for (Self.Tags.strings, 0..) |ext_str, j| {
                if (memcmp(u8, ext, ext_str)) {
                    const bit: u8 = (@as(u8, 0x01) << @as(u3, @intCast(j)));

                    if (ret & bit != 0)
                        return Error.repeated_extension;

                    ret |= bit;

                    continue :outer;
                }
            }

            return Error.unkown_extension;
        }

        return ret;
    }
};

const Principals = struct {
    ref: []const u8,

    const Self = @This();

    fn iter(self: *const Self) Self.Iterator {
        return .{
            .ref = self.ref,
            .off = 0,
        };
    }

    const Iterator = GenericIterator(
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

    fn from(buf: []const u8, magic: Magic) Error!RSA {
        return try parse(Self, magic, buf);
    }
};

pub const DSA = struct {
    magic: Magic,
    nonce: []const u8,
    p: []const u8, // TODO: mpint
    q: []const u8, // TODO: mpint
    g: []const u8, // TODO: mpint
    y: []const u8, // TODO: mpint
    serial: u64,
    kind: CertType,
    key_id: []const u8,
    valid_principals: Principals,
    valid_after: []const u8,
    valid_before: []const u8,
    critical_options: CriticalOptions,
    extensions: Extensions,
    reserved: []const u8,
    signature_key: []const u8,
    signature: []const u8,

    const Self = @This();

    fn from(buf: []const u8, magic: Magic) Error!DSA {
        return try parse(Self, magic, buf);
    }
};

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

    fn from(buf: []const u8, magic: Magic) Error!ECDSA {
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

    fn from(buf: []const u8, magic: Magic) Error!ED25519 {
        return try parse(ED25519, magic, buf);
    }
};

inline fn parse_cert_type(ref: []const u8) Error!struct { usize, CertType } {
    const next, const val = try parse_int(u32, ref);

    return .{ next, @enumFromInt(val) };
}

inline fn parse_critical_options(buf: []const u8) Error!struct { usize, CriticalOptions } {
    const next, const ref = try parse_string(buf);

    return .{ next, .{ .ref = ref } };
}

inline fn parse_principals(buf: []const u8) Error!struct { usize, Principals } {
    const next, const ref = try parse_string(buf);

    return .{ next, .{ .ref = ref } };
}

inline fn parse_extensions(buf: []const u8) Error!struct { usize, Extensions } {
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

inline fn read_int(comptime T: type, buf: []const u8) ?T {
    if (buf.len < @sizeOf(T))
        return null;

    return std.mem.readInt(T, buf[0..@sizeOf(T)], std.builtin.Endian.big);
}

inline fn parse_int(comptime T: type, buf: []const u8) Error!struct { usize, T } {
    if (read_int(T, buf)) |n|
        return .{ @sizeOf(T), n };

    return Error.malformed_integer;
}

inline fn parse_string(buf: []const u8) Error!struct { usize, []const u8 } {
    if (read_int(u32, buf)) |len| {
        const size = len + @sizeOf(u32);

        if (size > buf.len)
            return Error.malformed_string;

        return .{ size, buf[@sizeOf(u32)..size] };
    }

    return Error.malformed_string;
}

test "test parse rsa cert" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    try cert.parse(@embedFile("test/rsa-cert.pub"));

    switch (cert.kind) {
        .rsa => |c| {
            assert(c.magic == Magic.ssh_rsa);
            assert(c.serial == 2);
            assert(c.kind == CertType.user);
            assert(memcmp(u8, c.key_id, "abc"));

            var it = c.valid_principals.iter();
            assert(memcmp(u8, it.next().?, "root"));
            assert(it.done());

            assert(c.valid_after == 0);
            assert(c.valid_before == std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "test parse ecdsa cert" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    try cert.parse(@embedFile("test/ecdsa-cert.pub"));

    switch (cert.kind) {
        .ecdsa => |c| {
            assert(c.magic == Magic.ecdsa_sha2_nistp256);
            assert(c.serial == 2);
            assert(c.kind == CertType.user);
            assert(memcmp(u8, c.key_id, "abc"));

            var it = c.valid_principals.iter();
            assert(memcmp(u8, it.next().?, "root"));
            assert(it.done());

            assert(c.valid_after == 0);
            assert(c.valid_before == std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "test parse ed25519 cert" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    try cert.parse(@embedFile("test/ed25519-cert.pub"));

    switch (cert.kind) {
        .ed25519 => |c| {
            assert(c.magic == Magic.ssh_ed25519);
            assert(c.serial == 2);
            assert(c.kind == CertType.user);
            assert(memcmp(u8, c.key_id, "abc"));

            var it = c.valid_principals.iter();
            assert(memcmp(u8, it.next().?, "root"));

            assert(it.done());

            assert(c.valid_after == 0);
            assert(c.valid_before == std.math.maxInt(u64));
        },
        else => return error.wrong_certificate,
    }
}

test "test extensions iterator" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    const extensions = [_][]const u8{
        "permit-X11-forwarding",
        "permit-agent-forwarding",
        "permit-port-forwarding",
        "permit-pty",
        "permit-user-rc",
    };

    try cert.parse(@embedFile("test/rsa-cert.pub"));

    var it = cert.kind.rsa.extensions.iter();

    for (extensions) |extension| {
        assert(memcmp(u8, extension, it.next().?));
    }

    assert(it.done());
}

test "test extensions to bitflags" {
    const Ext = Extensions.Tags;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    try cert.parse(@embedFile("test/rsa-cert.pub"));

    assert(
        try cert.kind.rsa.extensions.to_bitflags() ==
            @intFromEnum(Ext.permit_agent_forwarding) |
            @intFromEnum(Ext.permit_X11_forwarding) |
            @intFromEnum(Ext.permit_user_rc) |
            @intFromEnum(Ext.permit_port_forwarding) |
            @intFromEnum(Ext.permit_pty),
    );
}

test "test multiple valid principals iterator" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    const valid_principals = [_][]const u8{ "foo", "bar", "baz" };

    try cert.parse(@embedFile("test/multiple-principals-cert.pub"));

    var it = cert.kind.rsa.valid_principals.iter();

    for (valid_principals) |principal| {
        assert(memcmp(u8, principal, it.next().?));
    }
}

test "test critical options iterator" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    try cert.parse(@embedFile("test/force-command-cert.pub"));

    const critical_options = [_]CriticalOption{.{
        .kind = .force_command,
        .value = "ls -la",
    }};

    var it = cert.kind.rsa.critical_options.iter();

    for (critical_options) |critical_option| {
        const opt = it.next().?;

        assert(critical_option.kind == opt.kind);
        assert(memcmp(u8, critical_option.value, opt.value));
    }

    assert(it.done());
}

test "test multiple critical options iterator" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    try cert.parse(@embedFile("test/multiple-critical-options-cert.pub"));

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

    var it = cert.kind.rsa.critical_options.iter();

    for (critical_options) |critical_option| {
        const opt = it.next().?;

        assert(critical_option.kind == opt.kind);
        assert(memcmp(u8, critical_option.value, opt.value));
    }

    assert(it.done());
}
