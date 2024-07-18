const std = @import("std");

const Encoder = std.base64.standard.Encoder;
const Decoder = std.base64.standard.Decoder;

const debug = std.debug.print;

pub const Error = error{
    CorruptedFile,
    ExpectedString,
    FailToParse,
    FileTooSmall,
    InvalidMagicString,
    MalformedInteger,
    MalformedString,
    RepeatedExtension,
    UnkownExtension,
};

fn enum_to_ssh_str(comptime T: type, sufix: []const u8) [std.meta.fields(T).len][]const u8 {
    switch (@typeInfo(T)) {
        .Enum => {},
        else => @compileError("Expected enum"),
    }

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
    const Self = @This();

    allocator: std.mem.Allocator,

    buf: ?[]u8 = null,

    kind: ?KeyType = null,

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
        for (MAGIC_STRINGS, 0..) |magic, i| {
            if (raw.len < magic.len) return error.FileTooSmall;

            if (std.mem.eql(u8, raw[0..magic.len], magic)) return switch (i) {
                0, 6, 7 => {
                    const data = if (self.get_der(raw)) |der| der else raw;

                    self.kind = .{
                        .RSA = try RSA.from(data, @enumFromInt(i)),
                    };
                },
                1 => {
                    const data = if (self.get_der(raw)) |der| der else raw;

                    self.*.kind = .{
                        .DSA = try DSA.from(data, @enumFromInt(i)),
                    };
                },
                2...4 => {
                    const data = if (self.get_der(raw)) |der| der else raw;

                    self.kind = .{
                        .ECDSA = try ECDSA.from(data, @enumFromInt(i)),
                    };
                },
                5 => {
                    const data = if (self.get_der(raw)) |der| der else raw;

                    self.*.kind = .{
                        .ED25519 = try ED25519.from(data, @enumFromInt(i)),
                    };
                },
                else => unreachable,
            };
        }

        // Try to parse pem

        return Error.InvalidMagicString;
    }
};

pub const KeyType = union(enum) {
    RSA: RSA,
    DSA: DSA,
    ECDSA: ECDSA,
    ED25519: ED25519,
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
};

const MAGIC_STRINGS = enum_to_ssh_str(Magic, "-cert-v01@openssh.com");

pub const CertType = enum(u32) {
    USER = 1,
    HOST = 2,
};

pub const Extensions = enum(u8) {
    // Flag indicating that signatures made with this certificate need not assert FIDO user presence. This option only
    // makes sense for the U2F/FIDO security key types that support this feature in their signature formats.
    no_touch_required = 0x01 << 0,

    // Flag indicating that X11 forwarding should be permitted. X11 forwarding will be refused if this option is absent.
    permit_X11_forwarding = 0x01 << 1,

    // Flag indicating that agent forwarding should be allowed. Agent forwarding must not be permitted unless this option is present.
    permit_agent_forwarding = 0x01 << 2,

    // Flag indicating that port-forwarding should be allowed. If this option is not present, then no port forwarding will be allowed.
    permit_port_forwarding = 0x01 << 3,

    // Flag indicating that PTY allocation should be permitted. In the absence of this option PTY allocation will be disabled.
    permit_pty = 0x01 << 4,

    // Flag indicating that execution of ~/.ssh/rc should be permitted. Execution of this script will not be permitted if this option is not present.
    permit_user_rc = 0x01 << 5,

    fn as_bitflags(buf: []const u8) Error!u8 {
        var ret: u8 = 0;

        var i: usize = 0;

        outer: while (i < buf.len) {
            const v = try parse_string(buf[i..]);

            if (v.@"1".len == 0) { // FIXME: This should me an iterator
                i += @sizeOf(u32);

                continue :outer;
            }

            for (EXTENSIONS_STRINGS, 0..) |e, j| {
                if (e.len != v.@"1".len)
                    continue;

                if (std.mem.eql(u8, e, v.@"1")) {
                    const bit: u8 = (@as(u8, 0x01) << @as(u3, @intCast(j)));

                    if (ret & bit != 0) return Error.RepeatedExtension;

                    ret |= bit;

                    i += v.@"0";

                    continue :outer;
                }
            }

            return Error.UnkownExtension;
        }

        return ret;
    }
};

const EXTENSIONS_STRINGS = enum_to_ssh_str(Extensions, "");

test "extensions to bitflag" {
    const data = [_]u8{ 0, 0, 0, 21, 112, 101, 114, 109, 105, 116, 45, 88, 49, 49, 45, 102, 111, 114, 119, 97, 114, 100, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 23, 112, 101, 114, 109, 105, 116, 45, 97, 103, 101, 110, 116, 45, 102, 111, 114, 119, 97, 114, 100, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 22, 112, 101, 114, 109, 105, 116, 45, 112, 111, 114, 116, 45, 102, 111, 114, 119, 97, 114, 100, 105, 110, 103, 0, 0, 0, 0, 0, 0, 0, 10, 112, 101, 114, 109, 105, 116, 45, 112, 116, 121, 0, 0, 0, 0, 0, 0, 0, 14, 112, 101, 114, 109, 105, 116, 45, 117, 115, 101, 114, 45, 114, 99, 0, 0, 0, 0 };

    const e = try Extensions.as_bitflags(&data);

    std.debug.assert(e ==
        @intFromEnum(Extensions.permit_agent_forwarding) |
        @intFromEnum(Extensions.permit_X11_forwarding) |
        @intFromEnum(Extensions.permit_user_rc) |
        @intFromEnum(Extensions.permit_port_forwarding) |
        @intFromEnum(Extensions.permit_pty));
}

const ExtensionsFlags = u8;

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
    extensions: ExtensionsFlags,
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

    var i: usize = MAGIC_STRINGS[@intFromEnum(magic)].len + @sizeOf(u32);

    inline for (std.meta.fields(T)) |f| {
        const val = switch (f.type) {
            []const u8 => try parse_string(buf[i..]),
            u64 => try parse_int(u64, buf[i..]),
            CertType => blk: {
                const r = try parse_int(u32, buf[i..]);
                break :blk .{ r.@"0", @as(CertType, @enumFromInt(r.@"1")) };
            },
            ExtensionsFlags => try parse_extensions(buf[i..]),

            else => continue,
        };

        i += val.@"0";

        @field(ret, f.name) = val.@"1";
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

    return Error.MalformedInteger;
}

inline fn parse_string(buf: []const u8) Error!struct { usize, []const u8 } {
    if (read_int(u32, buf)) |len| {
        if (len + @sizeOf(u32) > buf.len)
            return Error.MalformedString;

        return .{ @sizeOf(u32) + len, buf[@sizeOf(u32) .. @sizeOf(u32) + len] };
    }

    return Error.ExpectedString;
}

inline fn parse_extensions(buf: []const u8) Error!struct { usize, u8 } {
    const v = try parse_string(buf);

    const b = try Extensions.as_bitflags(v.@"1");

    return .{ v.@"0", b };
}

test "parse rsa cert" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    try cert.parse(@embedFile("test/rsa-cert.pub"));

    switch (cert.kind.?) {
        .RSA => {},
        else => return error.WrongCertificate,
    }
}

test "parse ecdsa cert" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    try cert.parse(@embedFile("test/ecdsa-cert.pub"));

    switch (cert.kind.?) {
        .ECDSA => {},
        else => return error.WrongCertificate,
    }
}

test "parse ed25519 cert" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var cert = Cert.init(gpa.allocator());
    defer cert.deinit();

    try cert.parse(@embedFile("test/ed25519-cert.pub"));

    switch (cert.kind.?) {
        .ED25519 => {},
        else => return error.WrongCertificate,
    }
}
