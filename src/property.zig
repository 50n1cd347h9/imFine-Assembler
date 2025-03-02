pub fn runTest(testname: []const u8) void {
    dbgprint("{s}\n", .{testname});
}

pub fn TestCase(comptime Expected: anytype) type {
    return Tuple(&[_]type{
        []const u8, // input
        switch (@typeInfo(@TypeOf(Expected))) {
            .@"struct" => Tuple(&Expected),
            else => Expected,
        },
    });
}

const std = @import("std");
const Tuple = std.meta.Tuple;
const dbgprint = std.debug.print;
