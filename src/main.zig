const std = @import("std");
const io = std.io;
const fs = std.fs;
const stdin = io.getStdIn().reader();
const stdout = io.getStdOut().writer();
const process = std.process;
const print = std.debug.print;
const eql = std.mem.eql;
const ArrayList = std.ArrayList;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};

const instructions = [_][]const u8{ "push", "pop", "add", "sub", "mul", "div", "and", "or", "xor", "shl", "ldr", "ldm", "cmp", "jmp", "jg", "jz", "jl", "nop" };

const registers = [_][]const u8{ "ip", "sp", "fp", "gr0", "gr1", "flag" };

const ImFineAssembly = struct {
    source_file: std.fs.File,
    input_reader: std.fs.File.Reader,
    line_buffer: [0x100]u8,
    token: Token,
    curr_line_code: Code,
    allocator: std.mem.Allocator,

    var str_BC_map: [instructions.len + registers.len]StrBc = undefined;
    var begin_idx: u32 = 0;
    var curr_idx: u32 = 0;

    const Token = enum {
        Register,
        Instruciton,
        Imm,
        Ref,
        InvalidToken,
    };
    const StrBc = struct {
        name: []const u8,
        bc: u8,
    };
    const Code = struct {
        opcode: u8,
        ext: u2,
        len: u3,
        first_oprand: u3,
        padding: u2,
        second_oprand: u128,
    };

    const BC_push: u8 = 0x0;
    const BC_pop: u8 = 0x1;
    const BC_add: u8 = 0x2;
    const BC_sub: u8 = 0x3;
    const BC_mul: u8 = 0x4;
    const BC_div: u8 = 0x5;
    const BC_and: u8 = 0x6;
    const BC_or: u8 = 0x7;
    const BC_xor: u8 = 0x8;
    const BC_shl: u8 = 0x9;
    const BC_ldr: u8 = 0xa;
    const BC_ldm: u8 = 0xb;
    const BC_cmp: u8 = 0xc;
    const BC_jmp: u8 = 0xd;
    const BC_jg: u8 = 0xf;
    const BC_jz: u8 = 0x10;
    const BC_jl: u8 = 0x11;
    const BC_nop: u8 = 0x12;

    const BC_reg_ip: u8 = 0b000;
    const BC_reg_sp: u8 = 0b001;
    const BC_reg_fp: u8 = 0b010;
    const BC_reg_flag: u8 = 0b011;
    const BC_reg_gr0: u8 = 0b100;
    const BC_reg_gr1: u8 = 0b101;

    const COMMA: u8 = ',';
    const SEMICOLON: u8 = ';';
    const SPACE: u8 = ' ';
    const SQUARE_BRACKET_OPEN = '[';
    const SQUARE_BRACKET_CLOSE = ']';

    fn init(self: *ImFineAssembly, allocator: std.mem.Allocator) !void {
        self.allocator = allocator;
        for (instructions, 0..) |instruction, i| {
            str_BC_map[i].name = instruction;
            str_BC_map[i].bc = @as(u8, @intCast(i));
        }
        for (registers, 0..) |register, i| {
            str_BC_map[instructions.len + i].name = register;
            str_BC_map[instructions.len + i].bc = @as(u8, @intCast(i));
        }
    }

    fn getBc(bcmap: [*]StrBc, name: []const u8) u8 {
        for (0..str_BC_map.len) |i| {
            if (std.mem.eql(u8, bcmap[i].name, name))
                return bcmap[i].bc;
        }
        return 0;
    }

    fn isSmallLetterOrDigit(char: u8) bool {
        switch (char) {
            'a'...'z', '0'...'9' => return true,
            else => return false,
        }
    }

    fn isRegister(buf: []u8) bool {
        for (registers) |register|
            if (std.mem.eql(u8, buf, register))
                return true;
        return false;
    }

    fn isOpcode(buf: []u8) bool {
        for (instructions) |instruction|
            if (std.mem.eql(u8, buf, instruction))
                return true;
        return false;
    }

    fn nextChar(buf: []u8) u8 {
        return buf[0];
    }

    fn nextToken(self: *ImFineAssembly) Token {
        const buf_end = self.line_buffer.len;
        for (self.line_buffer[begin_idx..buf_end], 0..) |char, i| {
            switch (char) {
                SPACE, COMMA => continue,
                SQUARE_BRACKET_OPEN => {
                    begin_idx += @as(u32, @intCast(i));
                    curr_idx = begin_idx;

                    while (nextChar(self.line_buffer[curr_idx..buf_end]) != SQUARE_BRACKET_CLOSE)
                        curr_idx += 1;
                },
                else => {
                    begin_idx += @as(u32, @intCast(i));
                    curr_idx = begin_idx;

                    while (isSmallLetterOrDigit(nextChar(self.line_buffer[curr_idx..buf_end]))) {
                        curr_idx += 1;
                    }
                    if (isOpcode(self.line_buffer[begin_idx..curr_idx])) {
                        begin_idx = curr_idx;
                        return Token.Instruciton;
                    }
                    //                    print("/hug{s}/\n", .{self.line_buffer[begin_idx..curr_idx]});
                    if (isRegister(self.line_buffer[begin_idx..curr_idx])) {
                        begin_idx = curr_idx;
                        return Token.Register;
                    }
                },
            }
        }
        return Token.InvalidToken;
    }

    fn nextLine(self: *ImFineAssembly) ?[]const u8 {
        const res = self.input_reader.readUntilDelimiterOrEof(
            &self.line_buffer,
            '\n',
        ) catch null;
        if (res) |line| {
            _ = line;
        } else {
            return null;
        }
        if (@import("builtin").os.tag == .windows) {
            return std.mem.trimRight(u8, self.line_buffer, "\r");
        } else {
            return &self.line_buffer;
        }
    }

    fn assemble(self: *ImFineAssembly, file_name: []const u8) !void {
        self.source_file = try fs.cwd().openFile(
            file_name,
            .{ .mode = .read_only },
        );
        defer self.source_file.close();
        self.input_reader = self.source_file.reader();

        //print("{any}\n", .{str_BC_map});
        print("{x}\n", .{getBc(&str_BC_map, "gr0")});
        while (self.nextLine() != null) {
            curr_idx = 0;
            begin_idx = 0;
            self.curr_line_code = undefined;

            token: while (true) {
                self.token = self.nextToken();
                switch (self.token) {
                    Token.Instruciton => continue,
                    Token.Register => break :token,
                    Token.Imm => return,
                    Token.Ref => return,
                    else => break :token,
                }
            }

            break;
        }
        // var buf_reader = std.io.bufferedReader(self.source_file.reader());
        // const input_reader = buf_reader.reader();
        // while (try input_reader.readUntilDelimiterOrEof(
        //     &self.line_buffer,
        //     '\n',
        // )) |line| {
        //     print("{s}\n", .{line});
        // }
    }
};

// *const [][:0]u8 = pointer to an array of zero terminated const u8 values
// fn parseArgs(args_p: *const [][:0]u8) ?void {
//     if (args_p.len < 2) {
//         return null;
//     }
//
//     for (args_p.*, 0..) |arg, i| {
//         if (eql(u8, arg, "-i")) {
//             return interactiveAsm();
//         } else if (eql(u8, arg, "-o")) {
//             const output_name: []u8 = args_p[i + 1];
//             return assemble(output_name);
//         } else {
//             continue;
//         }
//     }
//
//     return 0;
// }

pub fn main() !void {
    const args = try process.argsAlloc(std.heap.page_allocator);
    defer process.argsFree(std.heap.page_allocator, args);

    const filename = "test.asm";

    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        _ = deinit_status;
    }

    var hoge: ImFineAssembly = undefined;
    hoge.init(allocator) catch |err| {
        print("err = {!}\n", .{err});
    };
    hoge.assemble(filename) catch |err| {
        print("err = {!}\n", .{err});
    };
    //_ = parseArgs(&args);
}
