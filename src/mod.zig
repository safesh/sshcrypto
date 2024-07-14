const std = @import("std");

pub fn hello_world() void {
    std.debug.print("Hello, World!", .{});
}
