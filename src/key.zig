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
