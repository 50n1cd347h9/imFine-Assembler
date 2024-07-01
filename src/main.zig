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

fn toLSB(num: u128, index: usize) u8 {
    const mask: u32 = 0xff;
    const ofs: u5 = @intCast(index);
    const byte = shr(u128, num, ofs * 8) & mask;
    return @as(u8, @intCast(byte));
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

const ImFineAssembly = struct {
    src_name: []u8,
    dst_name: []u8,
    src_file: std.fs.File,
    dst_file: std.fs.File,
    input_reader: std.fs.File.Reader,
    output_writer: std.fs.File.Writer,
    line_buffer: [0x100]u8,
    token: Token,
    tokens: [][]u8,
    curr_line_code: Code,
    codes: ArrayList(Code),
    out_buf: ArrayList(u8),

    const COMMA: u8 = ',';
    const SEMICOLON: u8 = ';';
    const SPACE: u8 = ' ';
    const SQUARE_BRACKET_OPEN = '[';
    const SQUARE_BRACKET_CLOSE = ']';
    const EOL = '\x00';
    const BC_imm: u2 = 0b00;
    const BC_reg: u2 = 0b01;
    const BC_imm_ref: u2 = 0b10;
    const BC_reg_ref: u2 = 0b11;

    var str_BC_map: [instructions.len + registers.len]StrBc = undefined;
    var begin_idx: u32 = 0;
    var curr_idx: u32 = 0;
    var allocator: std.mem.Allocator = undefined;
    const filename_len = 0x50;
    var file_name_buf: [filename_len * 2]u8 = undefined;

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

    const SyntaxError = error{
        CommaNeeded,
        CloseSquareBracketNeeded,
    };

    const ArgError = error{
        FileNotFound,
        TooFewArgs,
    };
    const Token = enum {
        Register,
        Opcode,
        Imm,
        ImmRef,
        RegRef,
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

        @memset(&file_name_buf, 0);
    }

    // *const [][:0]u8 = pointer to an array of zero terminated const u8 values
    fn parseArgs(self: *ImFineAssembly, args_p: *const [][:0]u8) !void {
        if (args_p.len < 2) {
            return ArgError.TooFewArgs;
        }

        // for (args_p.*, 0..) |arg, i| {
        //     _ = i;
        // }
        copyForwards(u8, &file_name_buf, args_p.*[1]);
        self.asignOutputName();
    }

    fn asignOutputName(self: *ImFineAssembly) void {
        const extension = [4:0]u8{ '.', 'b', 'i', 'n' };

        const src_len = for (0..file_name_buf.len) |i| {
            if (file_name_buf[i] == EOL) {
                break @as(u8, @intCast(i));
            }
        } else blk: {
            break :blk @as(u8, @intCast(file_name_buf.len));
        };

        self.src_name = file_name_buf[0..src_len];

        const dst_len = for (0..src_len) |i| {
            if (file_name_buf[i] == '.') {
                break @as(u8, @intCast(i + extension.len));
            }
            file_name_buf[src_len + i] = self.src_name[i];
        } else blk: {
            break :blk @as(u8, @intCast(src_len + extension.len));
        };

        for (extension, 0..) |char, j| {
            file_name_buf[src_len + dst_len - extension.len + j] = char;
        }

        self.dst_name = file_name_buf[src_len .. src_len + dst_len];
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

    fn isRegister(buf: []const u8) bool {
        for (registers) |register|
            if (std.mem.eql(u8, buf, register))
                return true;
        return false;
    }

    fn isOpcode(buf: []const u8) bool {
        for (instructions) |instruction|
            if (std.mem.eql(u8, buf, instruction))
                return true;
        return false;
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

    fn getTokenType(buf: []const u8) Token {
        if (isOpcode(buf)) {
            return Token.Opcode;
        } else if (isImm(buf)) {
            return Token.Imm;
        } else if (isRegister(buf)) {
            return Token.Register;
        } else {
            return Token.InvalidToken;
        }
    }

    fn nextChar(buf: []u8) ?u8 {
        const char = if (buf.len > 1) buf[1] else null;
        return char;
    }

    fn nextToken(self: *ImFineAssembly, line: []u8) !?Token {
        const buf_end = line.len;
        var token_str: []u8 = undefined;
        var token_type: Token = undefined;
        defer {
            begin_idx = curr_idx;
        }

        for (line[begin_idx..buf_end], 0..) |char, i| {
            switch (char) {
                SEMICOLON, EOL => return null,
                SPACE, COMMA => continue,
                SQUARE_BRACKET_OPEN => {
                    begin_idx += @as(u32, @intCast(i));
                    curr_idx = begin_idx;

                    while (nextChar(line[curr_idx..buf_end])) |next| {
                        curr_idx += 1;
                        if (next == SQUARE_BRACKET_CLOSE) {
                            curr_idx += 1;
                            break;
                        }
                    } else {
                        return SyntaxError.CloseSquareBracketNeeded;
                    }

                    token_str = line[begin_idx + 1 .. curr_idx - 1];
                    token_type = switch (getTokenType(token_str)) {
                        Token.Register => |res| blk: {
                            // if opcode ld (ldm)
                            if (self.token == Token.Opcode) {
                                self.curr_line_code.opcode += 1;
                                self.curr_line_code.first_oprand = getBc(&str_BC_map, token_str);
                            } else {
                                if (!hasComma(line[0..begin_idx]) and self.token != Token.Opcode)
                                    return SyntaxError.CommaNeeded;
                                self.curr_line_code.second_oprand = getBc(&str_BC_map, token_str);
                                self.curr_line_code.ext = BC_reg_ref;
                            }
                            break :blk res;
                        },
                        Token.Imm => |res| blk: {
                            const int_num = toInt(token_str);
                            if (!hasComma(line[0..begin_idx]) and self.token != Token.Opcode)
                                return SyntaxError.CommaNeeded;
                            self.curr_line_code.second_oprand = int_num;
                            self.curr_line_code.ext = BC_imm_ref;
                            break :blk res;
                        },
                        else => Token.InvalidToken,
                    };

                    return token_type;
                },
                else => {
                    begin_idx += @as(u32, @intCast(i));
                    curr_idx = begin_idx;

                    while (nextChar(line[curr_idx..buf_end])) |next| {
                        curr_idx += 1;
                        if (!isLetterOrDigit(next))
                            break;
                    } else {
                        curr_idx += 1;
                    }

                    token_str = line[begin_idx..curr_idx];
                    token_type = switch (getTokenType(token_str)) {
                        Token.Opcode => |res| blk: {
                            self.curr_line_code.opcode = getBc(&str_BC_map, token_str);
                            break :blk res;
                        },
                        Token.Register => |res| blk: {
                            if (hasComma(line[begin_idx..buf_end])) {
                                self.curr_line_code.first_oprand = getBc(&str_BC_map, token_str);
                            } else {
                                if (!hasComma(line[0..begin_idx]) and self.token != Token.Opcode)
                                    return SyntaxError.CommaNeeded;
                                self.curr_line_code.second_oprand = getBc(&str_BC_map, token_str);
                                self.curr_line_code.ext = BC_reg;
                            }
                            break :blk res;
                        },
                        Token.Imm => |res| blk: {
                            const int_num = toInt(token_str);
                            self.curr_line_code.second_oprand = int_num;
                            self.curr_line_code.ext = BC_imm;
                            break :blk res;
                        },
                        else => Token.InvalidToken,
                    };

                    print("{s}\n", .{token_str});
                    return token_type;
                },
            }
        }

        return null;
    }

    fn toBinary(self: *ImFineAssembly) !void {
        var buf: [0x50]u8 = undefined;

        for (self.codes.allocatedSlice()[0..self.codes.items.len]) |*code| {
            var index: u8 = 2;
            code.len = switch (code.second_oprand) {
                0 => 0b000,
                1...(pow(u16, 2, 8) - 1) => 0b001,
                pow(u16, 2, 8)...(pow(u32, 2, 16) - 1) => 0b010,
                pow(u32, 2, 16)...(pow(u64, 2, 32) - 1) => 0b011,
                pow(u64, 2, 32)...(pow(u128, 2, 64) - 1) => 0b100,
                pow(u128, 2, 64)...(pow(u129, 2, 128) - 1) => 0b100,
            };
            const bytes: u8 = @divExact(pow(u8, 2, code.len + 2), 8);

            buf[0] = code.opcode << 2 | code.ext;
            buf[1] = @as(u8, @intCast(code.len)) << 5 | code.first_oprand << 2 | code.padding;
            for (0..bytes) |i| {
                const byte = toLSB(code.second_oprand, i);
                buf[2 + i] = byte;
                index += 1;
            }

            try self.out_buf.appendSlice(buf[0..index]);
        }
    }

    fn nextLine(self: *ImFineAssembly) !?[]u8 {
        @memset(&self.line_buffer, 0);
        const line = try self.input_reader.readUntilDelimiterOrEof(
            &self.line_buffer,
            '\n',
        );
        if (line == null)
            return line;
        if (@import("builtin").os.tag == .windows)
            std.mem.trimRight(u8, self.line_buffer, "\r");
        // skip empty line
        return if (line.?.len == 0) self.nextLine() else line;
    }

    fn assemble(self: *ImFineAssembly) !void {
        self.src_file = try fs.cwd().openFile(
            self.src_name,
            .{ .mode = .read_only },
        );
        defer self.src_file.close();
        self.input_reader = self.src_file.reader();
        self.codes = ArrayList(Code).init(allocator);
        defer self.codes.deinit();

        line: while (try self.nextLine()) |line| {
            curr_idx = 0;
            begin_idx = 0;
            self.curr_line_code = emptyCode();

            while (try self.nextToken(line)) |hoge| {
                self.token = hoge;
                switch (self.token) {
                    Token.Opcode => continue,
                    Token.Register => continue,
                    Token.Imm => continue,
                    Token.InvalidToken => break :line,
                }
            }

            if (true) {
                try stdout.print("{s}\n", .{line});
                try stdout.print("{!}\n\n", .{self.curr_line_code});
            }

            try self.codes.append(self.curr_line_code);
        }

        self.out_buf = ArrayList(u8).init(allocator);
        defer self.out_buf.deinit();
        try self.toBinary();

        self.dst_file = try fs.cwd().createFile(
            self.dst_name,
            .{},
        );
        defer self.dst_file.close();
        self.output_writer = self.dst_file.writer();
        try self.output_writer.writeAll(self.out_buf.items);
    }
};

pub fn main() !void {
    const args = try process.argsAlloc(std.heap.page_allocator);
    defer process.argsFree(std.heap.page_allocator, args);
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        _ = deinit_status;
    }

    var hoge: ImFineAssembly = undefined;
    hoge.init(allocator) catch |err| {
        print("{!}\n", .{err});
        return;
    };

    hoge.parseArgs(&args) catch |err| {
        print("{!}\n", .{err});
        return;
    };

    hoge.assemble() catch |err| {
        print("{!}\n", .{err});
        return;
    };
}
