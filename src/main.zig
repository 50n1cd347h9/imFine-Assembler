const std = @import("std");
const debugPrint = std.debug.print;
const c = std.c;
const fs = std.fs;
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

test "run label.bin" {
    const test_string =
        "Machine.ImFineMac{ .cpu = Machine.Cpu{ .ip = 36, .sp = 65535, .fp = 65535, .gr0 = 63, .gr1 = 0, .flag = 0 }, .memory = u8@10f91f8 }\n";

    const allocator = std.testing.allocator;
    var stdout_buf = std.ArrayList(u8).init(allocator);
    defer stdout_buf.deinit();
    var err_buf = std.ArrayList(u8).init(allocator);
    defer err_buf.deinit();

    const runvm = [_][]const u8{"./src/test.sh"};
    var child = std.process.Child.init(&runvm, allocator);
    child.stderr_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    try child.spawn();
    try child.collectOutput(&stdout_buf, &err_buf, 0x1000);
    _ = try child.wait();

    try std.testing.expect(std.mem.eql(
        u8,
        stdout_buf.items,
        test_string,
    ));
}
