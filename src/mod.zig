const std = @import("std");

const Encoder = std.base64.standard.Encoder;
const Decoder = std.base64.standard.Decoder;

const debug = std.debug.print;

pub const Error = error{
    FileTooSmall,
    InvalidMagicString,
    FailToParse,
    CorruptedFile,
    ExpectedString,
};

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
    SSH_RSA = 0,
    SSH_DSS = 1,
    ECDSA_SHA2_NISTP256 = 2,
    ECDSA_SHA2_NISTP384 = 3,
    ECDSA_SHA2_NISTP521 = 4,
    SSH_ED25519 = 5,
    RSA_SHA2_256 = 6,
    RSA_SHA2_512 = 7,

    // Unnecessary but cool
    fn make_magic_strings(comptime T: type) [std.meta.fields(T).len][]const u8 {
        const fields = std.meta.fields(T);

        comptime var ret: [fields.len][]const u8 = undefined;

        inline for (fields, &ret) |field, *r| {
            const U = [field.name.len]u8;

            comptime var name: U = std.mem.zeroes(U);

            inline for (field.name, &name) |c, *n| {
                n.* = if (c == '_') '-' else std.ascii.toLower(c);
            }

            r.* = name ++ "-cert-v01@openssh.com";
        }

        return ret;
    }
};

const MAGIC_STRINGS = Magic.make_magic_strings(Magic);

pub const CertType = enum(u32) {
    USER = 1,
    HOST = 2,
};

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

    var i: usize = MAGIC_STRINGS[@intFromEnum(magic)].len + @sizeOf(u32);

    inline for (std.meta.fields(T)) |f| {
        const val = switch (f.type) {
            []const u8 => try parse_string(buf[i..]),
            u64 => try parse_int(u64, buf[i..]),
            CertType => blk: {
                const r = try parse_int(u32, buf[i..]);
                break :blk .{ r.@"0", @as(CertType, @enumFromInt(r.@"1")) };
            },

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
    // debug("parse int = {X}\n", .{buf});

    if (read_int(T, buf)) |n|
        return .{ @sizeOf(T), n };

    return Error.FailToParse;
}

inline fn parse_string(buf: []const u8) Error!struct { usize, []const u8 } {
    // debug("parse string  = {X}\n", .{buf});

    if (read_int(u32, buf)) |len|
        return .{ @sizeOf(u32) + len, buf[@sizeOf(u32) .. @sizeOf(u32) + len] };

    return Error.ExpectedString;
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
