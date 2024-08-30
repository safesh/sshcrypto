const std = @import("std");

const Allocator = std.mem.Allocator;

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

fn enum_to_ssh_str(comptime T: type, sufix: []const u8) [std.meta.fields(T).len][]const u8 {
    if (@typeInfo(T) != .Enum)
        @compileError("Expected enum");

    const fields = std.meta.meta.fields(T);

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

pub const Magic = enum(u3) {
    ssh_rsa,

    const Self = @This();

    const strings = enum_to_ssh_str(Self, "");

    pub fn as_string(self: *const Self) []const u8 {
        return strings[@intFromEnum(self.*)];
    }
};

pub const Pem = struct {
    magic: []const u8,
    der: []u8,
    comment: []const u8,
};

pub const PemDecoder = struct {
    allocator: Allocator,
    decoder: std.base64.Base64Decoder,

    const Self = @This();

    pub const Der = struct {
        allocator: Allocator,
        magic: []const u8,
        ref: []u8,
        comment: []const u8,

        pub fn deinit(self: *Self.Der) void {
            self.allocator.free(self.ref);
        }
    };

    pub fn init(allocator: Allocator, decoder: std.base64.Base64Decoder) Self {
        return .{
            .allocator = allocator,
            .decoder = decoder,
        };
    }

    pub fn decode(self: *const Self, src: []const u8) Error!Self.Der {
        var it = std.mem.tokenizeAny(u8, src, " ");

        const magic = it.next() orelse
            return error.InvalidFileFormat;

        const ref = it.next() orelse
            return error.InvalidFileFormat;

        const comment = it.next() orelse
            return error.InvalidFileFormat;

        const len = try self.decoder.calcSizeForSlice(ref);

        const der = try self.allocator.alloc(u8, len);
        errdefer self.allocator.free(der);

        try self.decoder.decode(der, ref);

        return .{
            .allocator = self.allocator,
            .magic = magic,
            .ref = der,
            .comment = comment,
        };
    }
};
