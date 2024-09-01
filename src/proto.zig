const std = @import("std");

pub const Error = error{
    /// Invalid RFC-4251 integer
    MalformedInteger,
    /// Invalid RFC-4251 string
    MalformedString,
    /// Malformed RFC-4251 MpInt
    MalformedMpInt, // TODO:
    /// Object specific invalid data
    InvalidData,
};

pub fn enum_to_str(comptime T: type, sufix: []const u8) [std.meta.fields(T).len][]const u8 {
    if (@typeInfo(T) != .Enum) @compileError("Expected enum");

    const fields = comptime std.meta.fields(T);

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

// Parser continuation
pub fn Cont(comptime T: type) type {
    return struct {
        usize,
        T,
    };
}

pub const rfc4251 = struct {
    pub inline fn read_int(comptime T: type, buf: []const u8) ?T {
        if (buf.len < @sizeOf(T))
            return null;

        return std.mem.readInt(T, buf[0..@sizeOf(T)], std.builtin.Endian.big);
    }

    pub inline fn parse_int(comptime T: type, buf: []const u8) Error!struct { usize, T } {
        if (read_int(T, buf)) |n|
            return .{ @sizeOf(T), n };

        return Error.MalformedInteger;
    }

    pub inline fn parse_string(buf: []const u8) Error!struct { usize, []const u8 } {
        if (read_int(u32, buf)) |len| {
            const size = len + @sizeOf(u32);

            if (size > buf.len)
                return Error.MalformedString;

            return .{ size, buf[@sizeOf(u32)..size] };
        }

        return Error.MalformedString;
    }
};

pub inline fn parse(comptime T: type, src: []const u8) Error!T {
    var ret: T = undefined;

    var i: usize = 0;

    // TODO: Skip magic, since we need to verify it anyways

    inline for (comptime std.meta.fields(T)) |f| {
        const ref = src[i..];

        const next, const val = switch (comptime f.type) {
            []const u8 => try rfc4251.parse_string(ref),

            u64 => try rfc4251.parse_int(u64, ref),

            // TODO: Assert that the type has the parse method
            else => try f.type.parse(ref),
        };

        i += next;

        @field(ret, f.name) = val;
    }

    std.debug.assert(i == src.len);

    return ret;
}
