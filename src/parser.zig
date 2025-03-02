//! parser.zig is responsible for parsing assembly
//! and making identifier table

var token: Token = undefined;

const ParseError = error{
    CommaExpected,
    InstructionExpected,
    TokenAfterInstruction,
    NumberExpected,
    RegisterExpected,
    NewlineExpected,
    UnexpectedEof,
};

fn insPush(reader: anytype) void {
    _ = reader;
}

fn insAnd(reader: anytype) ParseError!void {
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp => {
            token = nextToken(reader);
            readComma(token) catch |e| return e;
            token = nextToken(reader);
            _ = readNumber(token) catch |e| return e;
        },
        else => return error.RegisterExpected,
    }
}

fn readComma(_token: Token) ParseError!void {
    if (_token.kind != .comma)
        return error.CommaExpected;
}

fn readNumber(_token: Token) ParseError!u32 {
    return switch (_token.kind) {
        .decLiteral, .hexLiteral => _token.val(),
        else => error.NumberExpected,
    };
}

fn readNewline(_token: Token) ParseError!void {
    return switch (_token.kind) {
        .newline => {},
        .eof => error.UnexpectedEof,
        else => error.NewlineExpected,
    };
}

fn readNlOrEof(_token: Token) ParseError!void {
    return switch (_token.kind) {
        .newline, .eof => {},
        else => ParseError.TokenAfterInstruction,
    };
}

fn labelDef(_: anytype) void {}

fn instruction(reader: anytype) ParseError!void {
    //dbgprint("tok: {s}\n", .{token.ident()});
    switch (token.kind) {
        .push => {
            token = nextToken(reader);
            insPush(reader);
        },
        .pop => {},
        .add => {},
        .sub => {},
        .mul => {},
        .div => {},
        .and_ => {
            token = nextToken(reader);
            insAnd(reader) catch |e| return e;
        },
        .or_ => {},
        .xor => {},
        .shl => {},
        .ld => {},
        .cmp => {},
        .jmp => {},
        .jg => {},
        .jz => {},
        .jl => {},
        .call => {},
        .ret => {},
        .nop => {},
        else => return error.InstructionExpected,
    }
}

fn program(reader: anytype) ParseError!void {
    token = nextToken(reader);

    while (token.kind == .newline)
        token = nextToken(reader);

    while (true) {
        //dbgprint("{}\n", .{token.kind});
        switch (token.kind) {
            .newline => {
                token = nextToken(reader);
            },
            .labelDef => {
                labelDef(reader);
                token = nextToken(reader);
                readNewline(token) catch |e| return e;
                token = nextToken(reader);
            },
            .eof => break,
            else => {
                instruction(reader) catch |e| return e;
                token = nextToken(reader);
                readNlOrEof(token) catch |e| return e;
                token = nextToken(reader);
            },
        }
    }
}

test "and instruction" {
    runTest("-- program --");

    defer testTokenizerInit();
    const program_str =
        \\and gr0, 1 
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try program(reader);
}

test "newline expected" {
    runTest("-- newline expected --");

    defer testTokenizerInit();
    const program_str =
        \\hoge:ahi
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.NewlineExpected, program(reader));
}

test "unexpected eof" {
    runTest("-- unexpected eof --");

    defer testTokenizerInit();
    const program_str =
        \\hoge:
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.UnexpectedEof, program(reader));
}

test "number expected" {
    runTest("-- number expected --");

    defer testTokenizerInit();
    const program_str =
        \\and gr0, x
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.NumberExpected, program(reader));
}

test "register expected" {
    runTest("-- register expected --");

    defer testTokenizerInit();
    const program_str =
        \\and XX, 1
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.RegisterExpected, program(reader));
}

test "comma expected" {
    runTest("-- comma expected --");

    defer testTokenizerInit();
    const program_str =
        \\and gr0 1
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.CommaExpected, program(reader));
}

test "instruction expected" {
    runTest("-- instruction expected --");

    defer testTokenizerInit();
    const program_str =
        \\gr0 1
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.InstructionExpected, program(reader));
}

test "and instruction fail" {
    runTest("-- and instruction fail --");

    defer testTokenizerInit();
    const program_str =
        \\and gr0, 1  ddd
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.TokenAfterInstruction, program(reader));
}

const std = @import("std");
const tokenizer = @import("tokenizer.zig");
const property = @import("property.zig");
const Token = tokenizer.Token;
const testTokenizerInit = tokenizer.testTokenizerInit;
const runTest = property.runTest;
const nextToken = tokenizer.nextToken;
const fbs = std.io.fixedBufferStream;
const dbgprint = std.debug.print;
const panic = std.debug.panic;
const expect = std.testing.expect;
const expectError = std.testing.expectError;
