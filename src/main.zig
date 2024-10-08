const std = @import("std");
const debugPrint = std.debug.print;
const process = std.process;
const Assembler = @import("./Assembler.zig");

pub fn main() !void {
    const args = try process.argsAlloc(std.heap.page_allocator);
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        process.argsFree(std.heap.page_allocator, args);
        const deinit_status = gpa.deinit();
        _ = deinit_status;
    }

    var assembler = Assembler.init(allocator);
    try assembler.parseArgs(&args);
    assembler.entry();
}
