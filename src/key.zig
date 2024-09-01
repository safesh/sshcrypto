const std = @import("std");

const proto = @import("proto.zig");

const Allocator = std.mem.Allocator;

pub const Error = error{
    InvalidMagicString,
} || proto.Error;

pub const Magic = enum(u3) {
    ssh_rsa,
    ecdsa_sha2_nistp256,
    ecdsa_sha2_nistp384,
    ecdsa_sha2_nistp521,
    ssh_ed25519,

    const Self = @This();

    const strings = proto.enum_to_str(Self, "");

    pub fn as_string(self: *const Self) []const u8 {
        return strings[@intFromEnum(self.*)];
    }

    fn parse(src: []const u8) Error!proto.Cont(Magic) {
        const next, const magic = try proto.Rfc4251.parse_string(src);

        for (Self.strings, 0..) |s, i|
            if (std.mem.eql(u8, s, magic))
                return .{ next, @enumFromInt(i) };

        return Error.InvalidMagicString;
    }

    pub fn from_bytes(src: []const u8) Error!Magic {
        _, const magic = try Self.parse(src);

        return magic;
    }
};

pub const Public = struct {
    pub const Pem = struct {
        magic: []const u8,
        der: []u8,
        comment: []const u8,
    };

    pub const RSA = struct {
        magic: Magic,
        e: []const u8, // TODO: mpint
        n: []const u8, // TODO: mpint

        const Self = @This();

        fn from(src: []const u8) Error!RSA {
            return try parse(Self, src);
        }

        pub inline fn from_bytes(src: []const u8) Error!RSA {
            return try Self.from(src);
        }

        pub inline fn from_pem(pem: Pem) Error!RSA {
            // XXX: Check if PEM magic matches what we got from the DER
            return try Self.from(pem.der);
        }
    };

    pub const ECDSA = struct {
        magic: Magic,
        nonce: []const u8,
        curve: []const u8,

        const Self = @This();

        fn from(src: []const u8) Error!ECDSA {
            return try parse(Self, src);
        }

        pub inline fn from_bytes(src: []const u8) Error!ECDSA {
            return try Self.from(src);
        }

        pub inline fn from_pem(pem: Pem) Error!ECDSA {
            // XXX: Check if PEM magic matches what we got from the DER
            return try Self.from(pem.der);
        }
    };

    pub const ED25519 = struct {
        magic: Magic,
        pk: []const u8,

        const Self = @This();

        fn from(src: []const u8) Error!ED25519 {
            return try parse(Self, src);
        }

        pub inline fn from_bytes(src: []const u8) Error!ED25519 {
            return try Self.from(src);
        }

        pub inline fn from_pem(pem: Pem) Error!ED25519 {
            // XXX: Check if PEM magic matches what we got from the DER
            return try Self.from(pem.der);
        }
    };
};

inline fn parse(comptime T: type, src: []const u8) Error!T {
    var ret: T = undefined;

    var i: usize = 0;

    inline for (comptime std.meta.fields(T)) |f| {
        const ref = src[i..];

        const next, const val = switch (f.type) {
            []const u8 => try proto.Rfc4251.parse_string(ref),

            u64 => try proto.Rfc4251.parse_int(u64, ref),

            // TODO: Assert that the type has the parse method
            else => try f.type.parse(ref),
        };

        i += next;

        @field(ret, f.name) = val;
    }

    std.debug.assert(i == src.len);

    return ret;
}
