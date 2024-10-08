const std = @import("std");
const ImFineAssembler = @import("Assembler.zig");
const ArrayList = std.ArrayList;
const SyntaxError = ImFineAssembler.SyntaxError;
const debugPrint = std.debug.print;

tokens: *ArrayList(?[]u8),
src_file_buf: [:0]u8,
const Tokenizer: type = @This();

const COMMA: u8 = ',';
const SEMICOLON: u8 = ';';
const SPACE: u8 = ' ';
const SQUARE_BRACKET_OPEN = '[';
const SQUARE_BRACKET_CLOSE = ']';
const INDENT = '\t';
const COLON: u8 = ':';
const EOL = '\x00';
const LABEL: u8 = 0b11 << 6;
const TOKEN_DELIMITER = '\x00';
const LINE_DELIMITER = '\n';

pub fn init(assembler: *ImFineAssembler) Tokenizer {
    return Tokenizer{
        .tokens = &assembler.tokens,
        .src_file_buf = assembler.src_file_buf,
    };
}

fn isLetterOrDigit(char: u8) bool {
    switch (char) {
        'a'...'z', 'A'...'Z', '0'...'9' => return true,
        else => return false,
    }
}

fn nextChar(buf: []u8) ?u8 {
    const char = if (buf.len > 2) buf[1] else null;
    return char;
}

fn nextToken(line: []u8, begin: *u32, curr: *u32) !?[]u8 {
    var begin_idx = begin.*;
    var curr_idx = curr.*;
    defer {
        begin.* = begin_idx;
        curr.* = curr_idx;
    }
    const buf_end = line.len;
    var token_str: ?[]u8 = null;

    while (begin_idx < buf_end) : (curr_idx += 1) {
        defer begin_idx = curr_idx;
        const char = line[begin_idx];
        switch (char) {
            SEMICOLON, EOL => break,
            SQUARE_BRACKET_CLOSE => return SyntaxError.OpenSquareBracketNeeded,
            SPACE, INDENT, COMMA => continue,
            SQUARE_BRACKET_OPEN => {
                while (nextChar(line[curr_idx..buf_end])) |next| {
                    curr_idx += 1;
                    if (next == SQUARE_BRACKET_CLOSE) {
                        curr_idx += 1;
                        break;
                    }
                } else return SyntaxError.CloseSquareBracketNeeded;
                token_str = line[begin_idx..curr_idx];
                break;
            },
            else => {
                while (nextChar(line[curr_idx..buf_end])) |next| {
                    defer curr_idx += 1;
                    if (isLetterOrDigit(next))
                        continue;
                    switch (next) {
                        SQUARE_BRACKET_CLOSE => return SyntaxError.OpenSquareBracketNeeded,
                        COLON => {
                            curr_idx += 2;
                            break;
                        },
                        else => break,
                    }
                } else curr_idx = @intCast(buf_end);
                token_str = line[begin_idx..curr_idx];
                break;
            },
        }
    }

    return token_str;
}

// is this variable necessary?
var src_buf_idx: usize = 0;
fn nextLine(src_buf: anytype) ?[]u8 {
    //    var src_buf_idx: usize = 0;
    const start = src_buf_idx;
    const line = for (src_buf[start..src_buf.len]) |char| {
        src_buf_idx += 1;
        if (char == LINE_DELIMITER)
            break src_buf[start..src_buf_idx];
    } else src_buf[start..src_buf.len];

    return if (line.len == 1 and line[0] == LINE_DELIMITER)
        nextLine(src_buf)
    else if (line.len == 0)
        null
    else
        line[0 .. line.len - 1];
}

pub fn tokenize(self: *Tokenizer) !void {
    while (nextLine(self.src_file_buf)) |line| {
        var begin_idx: u32 = 0;
        var curr_idx: u32 = 0;
        while (try nextToken(line, &begin_idx, &curr_idx)) |token|
            try self.tokens.append(token);
        try self.tokens.append(null);
    }
}
