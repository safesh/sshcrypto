const std = @import("std");

const Decoder = std.base64.standard.Decoder;

const debug = std.debug.print;

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

fn enum_to_ssh_str(comptime T: type, sufix: []const u8) [std.meta.fields(T).len][]const u8 {
    if (@typeInfo(T) != .Enum)
        @compileError("Expected enum");

    const fields = std.meta.fields(T);

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
        for (magic_strings, 0..) |magic, i| {
            if (raw.len < magic.len) return error.malformed_certificate;

            if (std.mem.eql(u8, raw[0..magic.len], magic)) return switch (i) {
                0, 6, 7 => {
                    const data = if (self.get_der(raw)) |der| der else raw;

                    self.kind = .{
                        .rsa = try RSA.from(data, @enumFromInt(i)),
                    };
                },
                1 => {
                    const data = if (self.get_der(raw)) |der| der else raw;

                    self.*.kind = .{
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

                    self.*.kind = .{
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

    fn as_string(self: *Self) []const u8 {
        return magic_strings[@intFromEnum(self)];
    }
};

const magic_strings = enum_to_ssh_str(Magic, "-cert-v01@openssh.com");

pub const CertType = enum(u32) {
    user = 1,
    host = 2,
};

/// The critical options section of the certificate specifies zero or more options on the certificate's validity.
pub const CriticalOptions = enum {
    /// Specifies a command that is executed (replacing any the user specified on the ssh command-line) whenever this key is used for authentication.
    force_command,

    /// Comma-separated list of source addresses from which this certificate is accepted for authentication. Addresses are specified in CIDR format
    /// (nn.nn.nn.nn/nn or hhhh::hhhh/nn). If this option is not present, then certificates may be presented from any source address.
    source_address,

    /// Flag indicating that signatures made with this certificate must assert FIDO user verification (e.g. PIN or biometric). This option only makes sense
    /// for the U2F/FIDO security key types that support this feature in their signature formats.
    verify_required,

    const Self = @This();

    pub fn iter(buf: []const u8) Self.Iterator {
        return Self.Iterator{
            .buf = buf,
            .off = 0,
        };
    }

    pub const Iterator = struct {
        buf: []const u8,
        off: usize,

        const Self = @This();

        /// Returns the next critical option, or null if done or an invalid option is found.
        pub fn next(self: *Iterator.Self) ?CriticalOption {
            if (self.off == self.buf.len) return null;

            const off, const ret = parse_string(self.buf[self.off..]) catch return null;

            self.off += off + @sizeOf(u32);

            return .{ .value = ret, .kind = CriticalOptions.force_command };
        }

        pub fn reset(self: *Iterator.Self) void {
            self.off = 0;
        }
    };
};

pub const CriticalOption = struct {
    kind: CriticalOptions,
    value: []const u8,
};

const critical_options_strings = enum_to_ssh_str(CriticalOptions, "");

/// The extensions section of the certificate specifies zero or more non-critical certificate extensions.
pub const Extensions = enum(u8) {
    /// Flag indicating that signatures made with this certificate need not assert FIDO user presence. This option only
    /// makes sense for the U2F/FIDO security key types that support this feature in their signature formats.
    no_touch_required = 0x01 << 0,

    /// Flag indicating that X11 forwarding should be permitted. X11 forwarding will be refused if this option is absent.
    permit_X11_forwarding = 0x01 << 1,

    /// Flag indicating that agent forwarding should be allowed. Agent forwarding must not be permitted unless this option is present.
    permit_agent_forwarding = 0x01 << 2,

    /// Flag indicating that port-forwarding should be allowed. If this option is not present, then no port forwarding will be allowed.
    permit_port_forwarding = 0x01 << 3,

    /// Flag indicating that PTY allocation should be permitted. In the absence of this option PTY allocation will be disabled.
    permit_pty = 0x01 << 4,

    /// Flag indicating that execution of ~/.ssh/rc should be permitted. Execution of this script will not be permitted if this option is not present.
    permit_user_rc = 0x01 << 5,

    const Self = @This();

    fn iter(buf: []const u8) Self.Iterator {
        return .{
            .buf = buf,
            .off = 0,
        };
    }

    const Iterator = struct {
        buf: []const u8,
        off: usize,

        const Self = @This();

        fn next(self: *Iterator.Self) ?[]const u8 {
            if (self.off == self.buf.len) return null;

            const off, const ret = parse_string(self.buf[self.off..]) catch return null;

            self.off += off + @sizeOf(u32);

            return ret;
        }

        fn reset(self: *Iterator.Self) void {
            self.off = 0;
        }
    };

    inline fn as_string(self: *Self) []const u8 {
        return extensions_strings[@intFromEnum(self)];
    }

    fn to_bitflags(buf: []const u8) Error!u8 {
        var ret: u8 = 0;

        var it = Self.iter(buf);

        outer: while (it.next()) |ext| {
            for (extensions_strings, 0..) |ext_str, j| {
                if (std.mem.eql(u8, ext, ext_str)) {
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

const extensions_strings = enum_to_ssh_str(Extensions, "");

test "extensions to bitflags" {
    const data = [_]u8{ 0, 0, 0, 21, 112, 101, 114, 109, 105, 116, 45, 88, 49, 49, 45, 102, 111, 114, 119, 97, 114, 100, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 23, 112, 101, 114, 109, 105, 116, 45, 97, 103, 101, 110, 116, 45, 102, 111, 114, 119, 97, 114, 100, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 22, 112, 101, 114, 109, 105, 116, 45, 112, 111, 114, 116, 45, 102, 111, 114, 119, 97, 114, 100, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 10, 112, 101, 114, 109, 105, 116, 45, 112, 116, 121, 0, 0, 0, 0, 0, 0, 0, 14, 112, 101, 114, 109, 105, 116, 45, 117, 115, 101, 114, 45, 114, 99, 0, 0, 0, 0 };

    const e = try Extensions.to_bitflags(&data);

    var it = Extensions.iter(&data);

    while (it.next()) |ext| {
        debug("ext = {s}\n", .{ext});
    }

    std.debug.assert(e ==
        @intFromEnum(Extensions.permit_agent_forwarding) |
        @intFromEnum(Extensions.permit_X11_forwarding) |
        @intFromEnum(Extensions.permit_user_rc) |
        @intFromEnum(Extensions.permit_port_forwarding) |
        @intFromEnum(Extensions.permit_pty));
}

test "critical options iterator" {
    const data = [_]u8{ 0, 0, 0, 21, 112, 101, 114, 109, 105, 116, 45, 88, 49, 49, 45, 102, 111, 114, 119, 97, 114, 100, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 23, 112, 101, 114, 109, 105, 116, 45, 97, 103, 101, 110, 116, 45, 102, 111, 114, 119, 97, 114, 100, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 22, 112, 101, 114, 109, 105, 116, 45, 112, 111, 114, 116, 45, 102, 111, 114, 119, 97, 114, 100, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 10, 112, 101, 114, 109, 105, 116, 45, 112, 116, 121, 0, 0, 0, 0, 0, 0, 0, 14, 112, 101, 114, 109, 105, 116, 45, 117, 115, 101, 114, 45, 114, 99, 0, 0, 0, 0 };

    var it = CriticalOptions.Iterator{
        .buf = &data,
        .off = 0,
    };

    while (it.next()) |opt| {
        debug("opt = {s}\n", .{opt.value});
    }
}

// const ExtensionsFlags = u8;

pub const RSA = struct {
    const Self = @This();

    magic: Magic,
    nonce: []const u8,
    e: []const u8, // TODO: mpint
    n: []const u8, // TODO: mpint
    serial: u64,
    kind: CertType,
    key_id: []const u8,
    valid_principals: []const u8,
    valid_after: u64,
    valid_before: u64,
    critical_options: []const u8,
    extensions: []const u8,
    reserved: []const u8,
    signature_key: []const u8,
    signature: []const u8,

    fn from(buf: []const u8, magic: Magic) Error!RSA {
        return try parse(Self, magic, buf);
    }
};

pub const DSA = struct {
    const Self = @This();

    magic: Magic,
    nonce: []const u8,
    p: []const u8, // TODO: mpint
    q: []const u8, // TODO: mpint
    g: []const u8, // TODO: mpint
    y: []const u8, // TODO: mpint
    serial: u64,
    kind: CertType,
    key_id: []const u8,
    valid_principals: []const u8,
    valid_after: []const u8,
    valid_before: []const u8,
    critical_options: []const u8,
    extensions: []const u8,
    reserved: []const u8,
    signature_key: []const u8,
    signature: []const u8,

    fn from(buf: []const u8, magic: Magic) Error!DSA {
        return try parse(Self, magic, buf);
    }
};

pub const ECDSA = struct {
    const Self = @This();

    magic: Magic,
    nonce: []const u8,
    curve: []const u8,
    public_key: []const u8,
    serial: u64,
    type: CertType,
    key_id: []const u8,
    valid_principals: []const u8,
    valid_after: u64,
    valid_before: u64,
    critical_options: []const u8,
    extensions: []const u8,
    reserved: []const u8,
    signature_key: []const u8,
    signature: []const u8,

    fn from(buf: []const u8, magic: Magic) Error!ECDSA {
        return try parse(Self, magic, buf);
    }
};

pub const ED25519 = struct {
    const Self = @This();

    magic: Magic,
    nonce: []const u8,
    pk: []const u8,
    serial: u64,
    kind: CertType,
    key_id: []const u8,
    valid_principals: []const u8,
    valid_after: u64,
    valid_before: u64,
    critical_options: []const u8,
    extensions: []const u8,
    reserved: []const u8,
    signature_key: []const u8,
    signature: []const u8,

    fn from(buf: []const u8, magic: Magic) Error!ED25519 {
        return try parse(ED25519, magic, buf);
    }
};

inline fn parse(comptime T: type, magic: Magic, buf: []const u8) Error!T {
    var ret: T = undefined;

    ret.magic = magic;

    var i: usize = magic_strings[@intFromEnum(magic)].len + @sizeOf(u32);

    inline for (std.meta.fields(T)) |f| {
        const next, const val = switch (f.type) {
            // RFC-4251 string
            []const u8 => try parse_string(buf[i..]),

            // RFC-4251 uint64
            u64 => try parse_int(u64, buf[i..]),

            // RFC-4251 uint32
            CertType => blk: {
                const next, const val = try parse_int(u32, buf[i..]);
                break :blk .{
                    next,
                    @as(CertType, @enumFromInt(val)),
                };
            },

            // RFC-4251 string
            // ExtensionsFlags => try parse_extensions(buf[i..]),

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

// inline fn parse_extensions(buf: []const u8) Error!struct { usize, u8 } {
//     const next, const str = try parse_string(buf);
//
//     return .{ next, try Extensions.as_bitflags(str) };
// }

test "parse rsa cert" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    try cert.parse(@embedFile("test/rsa-cert.pub"));

    switch (cert.kind) {
        .rsa => {},
        else => return error.wrong_certificate,
    }
}

test "parse ecdsa cert" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    try cert.parse(@embedFile("test/ecdsa-cert.pub"));

    switch (cert.kind) {
        .ecdsa => {},
        else => return error.wrong_certificate,
    }
}

test "parse ed25519 cert" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    try cert.parse(@embedFile("test/ed25519-cert.pub"));

    switch (cert.kind) {
        .ed25519 => |c| {
            debug("critical_options = {s}\n", .{c.valid_principals});
        },
        else => return error.wrong_certificate,
    }
}
