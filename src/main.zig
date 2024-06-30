const std = @import("std");
const io = std.io;
const fs = std.fs;
const stdin = io.getStdIn().reader();
const stdout = io.getStdOut().writer();
const process = std.process;
const print = std.debug.print;
const eql = std.mem.eql;
const pow = std.math.pow;
const shr = std.math.shr;
const ArrayList = std.ArrayList;
const mem = std.mem;
const copyForwards = mem.copyForwards;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const builtin = std.builtin;

// the order is matter
// ldr, ldm
const instructions = [_][]const u8{ "push", "pop", "add", "sub", "mul", "div", "and", "or", "xor", "shl", "ld", "ld", "cmp", "jmp", "jg", "jz", "jl", "nop" };
const registers = [_][]const u8{
    "ip",
    "sp",
    "fp",
    "flag",
    "gr0",
    "gr1",
};

const ImFineAssembly = struct {
    src_file: std.fs.File,
    dst_file: std.fs.File,
    input_reader: std.fs.File.Reader,
    output_writer: std.fs.File.Writer,
    line_buffer: [0x100]u8,
    token: Token,
    curr_line_code: Code,
    codes: ArrayList(Code),

    const COMMA: u8 = ',';
    const SEMICOLON: u8 = ';';
    const SPACE: u8 = ' ';
    const SQUARE_BRACKET_OPEN = '[';
    const SQUARE_BRACKET_CLOSE = ']';
    const BC_imm: u2 = 0b00;
    const BC_reg: u2 = 0b01;
    const BC_imm_ref: u2 = 0b10;
    const BC_reg_ref: u2 = 0b11;

    var str_BC_map: [instructions.len + registers.len]StrBc = undefined;
    var begin_idx: u32 = 0;
    var curr_idx: u32 = 0;
    var allocator: std.mem.Allocator = undefined;

    const SyntaxError = error{
        CommaNeeded,
    };
    const Token = enum {
        Register,
        Instruciton,
        Imm,
        Ref,
        InvalidToken,
        End,
    };
    const StrBc = struct {
        name: []const u8,
        bc: u8,
    };
    const Code = struct {
        opcode: u8,
        ext: u2,
        len: u3,
        first_oprand: u8,
        padding: u2,
        second_oprand: u128,
    };

    const Int = struct {
        number: u128,
        len: u16,
    };

    fn init(self: *ImFineAssembly, _allocator: std.mem.Allocator) !void {
        _ = self;
        allocator = _allocator;
        for (instructions, 0..) |instruction, i| {
            str_BC_map[i].name = instruction;
            str_BC_map[i].bc = @as(u8, @intCast(i));
        }
        for (registers, 0..) |register, i| {
            str_BC_map[instructions.len + i].name = register;
            str_BC_map[instructions.len + i].bc = @as(u8, @intCast(i));
        }
    }

    fn emptyCode() Code {
        return Code{
            .opcode = 0,
            .ext = 0,
            .len = 0,
            .first_oprand = 0,
            .padding = 0,
            .second_oprand = 0,
        };
    }

    fn getBc(bcmap: [*]StrBc, name: []const u8) u8 {
        for (0..str_BC_map.len) |i| {
            if (std.mem.eql(u8, bcmap[i].name, name))
                return bcmap[i].bc;
        }
        return 0;
    }

    fn isLetterOrDigit(char: u8) bool {
        switch (char) {
            'a'...'z', 'A'...'Z', '0'...'9' => return true,
            else => return false,
        }
    }

    fn toInt(buf: []const u8) u128 {
        var res: ?u128 = 0;
        if (buf.len > 2 and buf[0] == '0' and buf[1] == 'x') {
            res = std.fmt.parseInt(u128, buf[2..buf.len], 16) catch null;
        } else {
            res = std.fmt.parseInt(u128, buf, 10) catch null;
        }
        if (res != null)
            return res.?;
        return res.?;
    }

    fn isImm(buf: []const u8) bool {
        var res: ?u128 = 0;
        for ([2]u8{ 10, 16 }) |base| {
            if (buf.len > 2 and buf[0] == '0' and buf[1] == 'x') {
                res = std.fmt.parseInt(u128, buf[2..buf.len], base) catch null;
            } else {
                res = std.fmt.parseInt(u128, buf, base) catch null;
            }
            if (base == 16) {
                if (res == null) {
                    return false;
                } else {
                    return true;
                }
            }
        }
        return false;
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

    fn hasComma(buf: []const u8) bool {
        for (buf) |char| {
            switch (char) {
                SEMICOLON => return false,
                COMMA => return true,
                else => continue,
            }
        }
        return false;
    }

    fn nextChar(buf: []u8) u8 {
        return buf[0];
    }

    fn nextToken(self: *ImFineAssembly) !Token {
        defer {
            begin_idx = curr_idx;
        }
        const buf_end = self.line_buffer.len;
        for (self.line_buffer[begin_idx..buf_end], 0..) |char, i| {
            switch (char) {
                '\x00' => return Token.InvalidToken,
                SPACE, COMMA => continue,
                SEMICOLON => return Token.InvalidToken,
                SQUARE_BRACKET_OPEN => {
                    begin_idx += @as(u32, @intCast(i));
                    curr_idx = begin_idx;

                    while (nextChar(self.line_buffer[curr_idx..buf_end]) != SQUARE_BRACKET_CLOSE)
                        curr_idx += 1;
                    curr_idx += 1;

                    const inner_str = self.line_buffer[begin_idx + 1 .. curr_idx - 1];

                    if (isRegister(inner_str)) {
                        // if opcode ld (ldm)
                        if (self.token == Token.Instruciton) {
                            self.curr_line_code.opcode += 1;
                            self.curr_line_code.first_oprand = getBc(&str_BC_map, inner_str);
                        } else {
                            if (!hasComma(self.line_buffer[0..begin_idx]) and self.token != Token.Instruciton)
                                return SyntaxError.CommaNeeded;
                            self.curr_line_code.second_oprand = getBc(&str_BC_map, inner_str);
                            self.curr_line_code.ext = BC_reg_ref;
                        }
                        return Token.Register;
                    }

                    if (isImm(inner_str)) {
                        const int_num = toInt(inner_str);
                        if (!hasComma(self.line_buffer[0..begin_idx]) and self.token != Token.Instruciton)
                            return SyntaxError.CommaNeeded;
                        self.curr_line_code.second_oprand = int_num;
                        self.curr_line_code.ext = BC_imm_ref;
                    }
                },
                else => {
                    begin_idx += @as(u32, @intCast(i));
                    curr_idx = begin_idx;

                    while (isLetterOrDigit(nextChar(self.line_buffer[curr_idx..buf_end]))) {
                        curr_idx += 1;
                    }

                    const token_str = self.line_buffer[begin_idx..curr_idx];

                    if (isOpcode(token_str)) {
                        self.curr_line_code.opcode = getBc(&str_BC_map, token_str);
                        return Token.Instruciton;
                    }

                    if (isRegister(token_str)) {
                        if (hasComma(self.line_buffer[begin_idx..buf_end])) {
                            self.curr_line_code.first_oprand = getBc(&str_BC_map, token_str);
                        } else {
                            if (!hasComma(self.line_buffer[0..begin_idx]) and self.token != Token.Instruciton)
                                return SyntaxError.CommaNeeded;
                            self.curr_line_code.second_oprand = getBc(&str_BC_map, token_str);
                            self.curr_line_code.ext = BC_reg;
                        }
                        return Token.Register;
                    }

                    if (isImm(token_str)) {
                        const int_num = toInt(token_str);
                        self.curr_line_code.second_oprand = int_num;
                        self.curr_line_code.ext = BC_imm;
                    }

                    return Token.InvalidToken;
                },
            }
        }
        return Token.InvalidToken;
    }

    fn toLSB(num: u128, index: usize) u8 {
        const mask: u32 = 0xff;
        const ofs: u5 = @intCast(index);
        const byte = shr(u128, num, ofs * 8) & mask;
        return @as(u8, @intCast(byte));
    }

    fn toBinary(self: *ImFineAssembly) !void {
        var out_buf = ArrayList(u8).init(allocator);
        defer out_buf.deinit();

        for (self.codes.allocatedSlice()[0..self.codes.items.len]) |*code| {
            code.len = switch (code.second_oprand) {
                0 => 0b000,
                1...(pow(u16, 2, 8) - 1) => 0b001,
                pow(u16, 2, 8)...(pow(u32, 2, 16) - 1) => 0b010,
                pow(u32, 2, 16)...(pow(u64, 2, 32) - 1) => 0b011,
                pow(u64, 2, 32)...(pow(u128, 2, 64) - 1) => 0b100,
                pow(u128, 2, 64)...(pow(u129, 2, 128) - 1) => 0b100,
            };
            const bytes: u8 = @divExact(pow(u8, 2, code.len + 2), 8);

            try out_buf.append(code.opcode << 2 | code.ext);
            try out_buf.append(code.opcode << 5 | code.first_oprand << 2 | code.padding);
            for (0..bytes) |i| {
                const byte = toLSB(code.second_oprand, i);
                try out_buf.append(byte);
            }

            print("{!}\n", .{code});
        }
        stdout.print("{s}\n", .{out_buf.items}) catch unreachable;
        //            self.output_writer.write(code.opcode << 5 | code.first_oprand << 2 | code.padding);
    }

    fn nextLine(self: *ImFineAssembly) ?[]const u8 {
        @memset(&self.line_buffer, 0);
        const res = self.input_reader.readUntilDelimiterOrEof(
            &self.line_buffer,
            '\n',
        ) catch null;
        std.mem.replaceScalar(u8, &self.line_buffer, '\n', '\x00');

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
        self.src_file = try fs.cwd().openFile(
            file_name,
            .{ .mode = .read_only },
        );
        self.dst_file = try fs.cwd().createFile(
            "hoge.bin",
            .{},
        );
        defer self.src_file.close();
        defer self.dst_file.close();
        self.input_reader = self.src_file.reader();
        self.output_writer = self.dst_file.writer();
        self.codes = ArrayList(Code).init(allocator);
        defer self.codes.deinit();

        line: while (self.nextLine() != null) {
            curr_idx = 0;
            begin_idx = 0;
            self.curr_line_code = emptyCode();

            token: while (true) {
                self.token = try self.nextToken();
                switch (self.token) {
                    Token.Instruciton => continue,
                    Token.Register => continue,
                    Token.Imm => continue,
                    Token.Ref => continue,
                    Token.InvalidToken => if (begin_idx == 0) {
                        break :line;
                    } else {
                        try self.codes.append(self.curr_line_code);
                        break :token;
                    },
                    else => break :line,
                }
            }
        }
        try self.toBinary();
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
