pub var tokens: Tokens = Tokens{};
var _ch: u8 = ' ';
var buffer: [0x1000]u8 = undefined;
var fba = std.heap.FixedBufferAllocator.init(&buffer);
const a = fba.allocator();

pub fn init() void {
    _ch = ' ';
    tokens.clearAndFree(a);
    //tokens.setCapacity(MAX_TOKENS);
}

pub fn deinit() void {
    _ch = ' ';
    tokens.clearAndFree(a);
    //tokens.deinit(a);
}

pub fn testTokenizerInit() void {
    _ch = ' ';
}

pub const TokenKindTag = enum {
    register,
    instruction,
    macro,
    number,
    character,
    label,
};

pub const TokenKind = union(TokenKindTag) {
    register: Register,
    instruction: Instruction,
    macro: Macro,
    number: Number,
    character: Character,
    label: Label,

    const Label = enum {
        def,
        slot,
    };

    const Register = enum {
        ip,
        flag,
        sp,
        fp,
        gr0,
        gr1,
    };

    const Number = enum {
        dec,
        hex,
    };

    const Instruction = enum {
        push,
        pop,
        add,
        sub,
        mul,
        div,
        and_,
        or_,
        xor,
        shl,
        ld,
        cmp,
        jmp,
        jg,
        jz,
        jl,
    };

    const Macro = enum {
        call,
        ret,
        mov,
        nop,
    };

    const Character = enum {
        comma,
        newline,
        sqbrac_l,
        sqbrac_r,
        eof,
    };

    // instruction
    // macro
    // register
    pub fn get(buf: []const u8) ?TokenKind {
        const str2enum = std.meta.stringToEnum;

        var kind: TokenKind = undefined;

        if (str2enum(Macro, buf)) |macro| {
            kind.macro = macro;
        } else if (str2enum(Instruction, buf)) |instruction| {
            kind.instruction = instruction;
        } else if (str2enum(Register, buf)) |register| {
            kind.register = register;
        } else {
            var tmp = [_]u8{'_'} ** MAX_IDENT_LEN;
            std.mem.copyForwards(u8, &tmp, buf);

            if (str2enum(Instruction, tmp[0 .. buf.len + 1])) |instruction|
                kind.instruction = instruction;
        }

        return kind;
    }
};

const CharKind = enum {
    digit,
    letter,
    comma,
    eof,
    newline,
    colon,
    other,
    sqbrac_l,
    sqbrac_r,

    // TODO: define comment(#)
    pub fn get(ch: u8) CharKind {
        return switch (ch) {
            'a'...'z', 'A'...'Z' => .letter,
            '0'...'9' => .digit,
            '[' => .sqbrac_l,
            ']' => .sqbrac_r,
            '\n' => .newline,
            ',' => .comma,
            ':' => .colon,
            EOF => .eof,
            else => .other,
        };
    }
};

pub const Token = struct {
    kind: TokenKind,
    id: ?HashType, // nullable

    const hash_fn = std.hash.RapidHash.hash;
    const HashType: type = @typeInfo(@TypeOf(hash_fn)).@"fn".return_type.?;

    pub fn hash(input: []const u8) HashType {
        const hash_key = 0xdeadbeef;
        return hash_fn(hash_key, input);
    }
};

const Tokens: type = std.MultiArrayList(Token);

fn isRegister(token: []const u8) bool {
    for (registers) |register|
        return streql(token, register);
    return false;
}

fn isInstruction(token: []const u8) bool {
    for (instructions) |instruction|
        return streql(token, instruction);
    return false;
}

fn isKeyword(token: []const u8) bool {
    return isRegister(token) or isInstruction(token);
}

fn streql(one: []const u8, two: []const u8) bool {
    return std.mem.eql(u8, one, two);
}

fn isDigit(ch: u8) bool {
    const code = @as(i8, @bitCast(ch));
    return 0 <= code - '0' and code - '0' < 10;
}

fn isHex(ch: u8) bool {
    const code = @as(i8, @bitCast(ch));
    return (0 <= code - 'a' and code - 'a' < 6) or isDigit(ch);
}

fn isLetter(ch: u8) bool {
    const code = @as(i8, @bitCast(ch));
    return (0 <= code - 'a' and code - 'a' < 26) or (0 <= code - 'A' and code - 'A' < 26);
}

fn nextChar(reader: anytype) u8 {
    return reader.readByte() catch EOF;
}

pub fn nextToken(reader: anytype) Token {
    var kind: TokenKind = undefined;
    var num: u32 = 0;
    var buf: [MAX_IDENT_LEN]u8 = [_]u8{0} ** MAX_IDENT_LEN;
    var i: usize = 0;
    var ch = _ch;
    defer _ch = ch;

    while (ch == ' ' or ch == '\t')
        ch = nextChar(reader);

    switch (CharKind.get(ch)) {
        .digit => {
            //kind = .numberLiteral;
            kind.number = .dec;
            if (ch == '0') {
                i += 1;
                ch = nextChar(reader);

                if (ch == 'x') {
                    //kind = .hexLiteral;
                    kind.number = .hex;
                    i += 1;
                    ch = nextChar(reader);
                    while (isHex(ch)) {
                        num = num * 16 + (ch - '0');
                        i += 1;
                        ch = nextChar(reader);
                    }
                }
            } else {
                while (isDigit(ch)) {
                    num = num * 10 + (ch - '0');
                    i += 1;
                    ch = nextChar(reader);
                }
            }
        },
        .letter => {
            buf[i] = ch;
            i += 1;
            ch = nextChar(reader);

            while ((isLetter(ch) or isDigit(ch)) and i < MAX_IDENT_LEN) {
                buf[i] = ch;
                i += 1;
                ch = nextChar(reader);
            }

            if (TokenKind.get(buf[0..i])) |_kind| {
                kind = _kind;
            } else if (ch == ':') {
                kind.label = .def;
                ch = nextChar(reader);
            } else {
                kind.label = .slot;
            }
        },
        .newline => {
            kind.character = .newline;
            ch = nextChar(reader);
        },
        .comma => {
            kind.character = .comma;
            ch = nextChar(reader);
        },
        .sqbrac_l => {
            kind.character = .sqbrac_l;
            ch = nextChar(reader);
        },
        .sqbrac_r => {
            kind.character = .sqbrac_r;
            ch = nextChar(reader);
        },
        .eof => {
            kind.character = .eof;
        },
        else => {
            dbgprint("|{c}|{x}|\n", .{ ch, ch });
            @panic("character unaccepted");
        },
    }

    const token = Token{
        .kind = kind,
        .id = switch (kind) {
            .number => num,
            .label => Token.hash(buf[0..i]),
            else => null,
        },
        //.id = switch (kind) {
        //    .numberLiteral => num,
        //    .label, .labelDef => Token.hash(buf[0..i]),
        //    else => null,
        //},
    };

    tokens.append(a, token) catch @panic("aaaaaa");
    return token;
}

test "digit" {
    for (0..10) |i|
        try std.testing.expect(isDigit(@intCast('0' + i)));
    for ([_]u8{ ':', '/', '`', 'g' }) |ch|
        try std.testing.expect(!isDigit(ch));
}

test "hex" {
    for (0..10) |i|
        try std.testing.expect(isHex(@intCast('0' + i)));
    for (0..6) |i|
        try std.testing.expect(isHex(@intCast('a' + i)));
    for ([_]u8{ ':', '/', '`', 'g' }) |ch|
        try std.testing.expect(!isHex(ch));
}

test "letter" {
    for ('A'..'Z' + 1) |letter|
        try std.testing.expect(isLetter(@intCast(letter)));
    for ('a'..'z' + 1) |letter|
        try std.testing.expect(isLetter(@intCast(letter)));
    for ([_]u8{ ':', '.', '`', '_' }) |letter|
        try std.testing.expect(!isLetter(@intCast(letter)));
}

// TODO: test macros and characters

test "token kind" {
    const pass_cases = [_]TestCase(TokenKind.Instruction){
        .{ "and", .and_ },
        .{ "or", .or_ },
        .{ "ld", .ld },
        .{ "xor", .xor },
        //.{ "call", .call },
        //.{ "[", .sqbrac_l },
        //.{ "]", .sqbrac_r },
    };

    for (pass_cases) |case| {
        defer testTokenizerInit();
        const input, const kind = case;
        if (TokenKind.get(input)) |_kind|
            try std.testing.expect(_kind.instruction == kind);
    }
}

test "TokenKind accept all keywords" {
    for (keywds) |keywd|
        try std.testing.expect(TokenKind.get(keywd) != null);
}

test "number literal" {
    const Expected = .{ TokenKind.Number, u32 };
    const pass_cases = [_]TestCase(Expected){
        .{ "0x10 ", .{ .hex, 0x10 } },
        .{ "0x10", .{ .hex, 0x10 } },
        .{ "0", .{ .dec, 0 } },
        .{ "10", .{ .dec, 10 } },
        .{ "20000", .{ .dec, 20000 } },
    };
    for (pass_cases) |case| {
        defer testTokenizerInit();
        const input, const expected = case;
        const kind, const val = expected;

        var stream = fbs(input);
        const reader = stream.reader();
        const token = nextToken(reader);

        try std.testing.expect(token.kind.number == kind);
        try std.testing.expect(token.id == val);
    }
}

test "identifier" {
    const Expected = .{ []const u8, TokenKind.Label };
    const pass_cases = [_]TestCase(Expected){
        .{ "hoge", .{ "hoge", .slot } },
        .{ "hoge:", .{ "hoge", .def } },
    };

    const hoge = u8;
    _ = TestCase(hoge);

    for (pass_cases) |case| {
        defer testTokenizerInit();
        const input, const expected = case;
        const exptd_str, const kind = expected;
        //
        var stream = fbs(input);
        const reader = stream.reader();
        const token = nextToken(reader);

        try std.testing.expect(token.kind.label == kind);
        try std.testing.expect(Token.hash(exptd_str) == token.id);
    }
}

test "trailing identifier" {
    const Expected = .{
        []const []const u8, // tokenized identifiers
        []const TokenKind.Label,
    };
    // this fails: const pass_cases: []TestCase = .{ hogehoge };
    const pass_cases = [_]TestCase(Expected){
        .{ "trailing identifier ", .{ &.{ "trailing", "identifier" }, &.{ .slot, .slot } } },
        .{ "trailing: identifier ", .{ &.{ "trailing", "identifier" }, &.{ .def, .slot } } },
    };

    for (pass_cases) |case| {
        defer testTokenizerInit();
        const input, const expected = case;
        const strs, const kinds = expected;
        var stream = fbs(input);
        const reader = stream.reader();

        for (kinds, strs) |kind, exptd_str| {
            const token = nextToken(reader);
            try std.testing.expect(token.kind.label == kind);
            try std.testing.expect(Token.hash(exptd_str) == token.id.?);
        }
    }
}

test "program" {
    defer testTokenizerInit();
    const program_str =
        \\ld gr0, 4
        \\jmp aiueo
        \\hogehoge:
        \\shl gr0, 4
        \\jmp huga
        \\
        \\
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    var token = nextToken(reader);
    while (token.kind.character != .eof) {
        switch (token.kind) {
            .number => dbgprint("{d: <9} {}\n", .{ token.id.?, token.kind }),
            .label => dbgprint("{d: <9} {}\n", .{ token.id.?, token.kind }),
            else => {},
        }
        token = nextToken(reader);
    }
}

test "program2" {
    defer testTokenizerInit();
    const program_str =
        \\ld gr0, 4
        \\jmp aiueo
        \\hogehoge:
        \\shl gr0, 4
        \\jmp huga
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    var token = nextToken(reader);
    while (token.kind.character != .eof) {
        switch (token.kind) {
            .number => dbgprint("{d: <9} {}\n", .{ token.id.?, token.kind }),
            .label => dbgprint("{d: <9} {}\n", .{ token.id.?, token.kind }),
            else => {},
        }
        token = nextToken(reader);
    }
}

//test "and instruction" {
//    const program_str =
//        \\and gr0, 1
//        \\
//    ;
//    const Expected = []const TokenKind;
//    const pass_cases = [_]TestCase(Expected){
//        .{ program_str, &.{
//            .Instruction.and_,
//            .Register.gr0,
//            .Character.comma,
//            .Number.dec,
//            .Character.newline,
//            .Character.eof,
//        } },
//    };
//
//    var stream = fbs(program_str);
//    const reader = stream.reader();
//    for (pass_cases) |case| {
//        defer testTokenizerInit();
//        _, const expected = case;
//
//        for (expected) |kind| {
//            const token = nextToken(reader);
//            dbgprint("e: {}, a: {}\n", .{ kind, token.kind });
//            try std.testing.expect(token.kind == kind);
//        }
//    }
//}

const std = @import("std");
const property = @import("property.zig");
const consts = @import("consts.zig");
const parser = @import("parser.zig");
const registers = consts.registers;
const instructions = consts.instructions;
const dbgprint = std.debug.print;
const fbs = std.io.fixedBufferStream;
const Tuple = std.meta.Tuple;
const panic = std.debug.panic;
const TestCase = property.TestCase;
const runTest = property.runTest;
const MAX_IDENT_LEN = consts.MAX_IDENT_LEN;
const MAX_TOKEN_BUF = consts.MAX_TOKEN_BUF;
const MAX_TOKENS = consts.MAX_TOKENS;
const EOF = consts.EOF;
const keywds = consts.keywds;
