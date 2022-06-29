//! Hypertext Transfer Protocol (HTTP).

const std = @import("std");
const mem = std.mem;
const ascii = std.ascii;
const net = std.net;
const http = std.http;
const log = std.log;

const version = "HTTP/1.1";
const crlf = "\r\n";
const whitespace = [_]u8{ ' ', '\t' };

const Port = enum(u16) {
    unencrypted = 80,
    encrypted = 443,
};

pub const Response = struct {
    status: http.Status,
    body: ?[]const u8,
};

pub const Client = struct {
    stream: std.net.Stream,
    /// The mandatory "Host" header field.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc7230#section-5.4
    host_header_field_value: []const u8,

    pub fn init(allocator: mem.Allocator, hostname: []const u8, port: Port) !Client {
        return Client{
            .stream = try std.net.tcpConnectToHost(allocator, hostname, @enumToInt(port)),
            .host_header_field_value = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ hostname, @enumToInt(port) }),
        };
    }

    pub fn deinit(self: Client) void {
        self.stream.close();
    }

    const request = struct {
        fn createRequestLine(allocator: mem.Allocator, method: []const u8, request_target: []const u8) ![]u8 {
            // https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.1
            return std.fmt.allocPrint(allocator, "{s} {s} " ++ version ++ crlf, .{
                method,
                request_target,
            });
        }

        fn createField(allocator: mem.Allocator, name: []const u8, value: []const u8) ![]u8 {
            return std.fmt.allocPrint(allocator, "{s}:{s}" ++ crlf, .{
                name, value,
            });
        }

        fn createMessage(client: Client, allocator: mem.Allocator, method: []const u8, request_target: []const u8, body: ?[]const u8) ![]u8 {
            // https://datatracker.ietf.org/doc/html/rfc7230#section-3
            const start_line = try createRequestLine(allocator, method, request_target);
            const header_fields = try createField(allocator, "Host", client.host_header_field_value);
            if (body) |body_value|
                return std.fmt.allocPrint(allocator, "{s}{s}" ++ crlf ++ "{s}", .{
                    start_line, header_fields, body_value,
                })
            else
                return std.fmt.allocPrint(allocator, "{s}{s}" ++ crlf ++ "{s}", .{
                    start_line, header_fields, "",
                });
        }
    };

    const response = struct {
        const TransferEncoding = enum { chunked };
        const BodySpecifier = union(enum) {
            content_length: usize,
            transfer_encoding: TransferEncoding,
        };

        fn readMessage(allocator: mem.Allocator, reader: anytype) !Response {
            const status = try readStatusLine(allocator, reader);
            log.debug("status: {}", .{status});

            // https://datatracker.ietf.org/doc/html/rfc7230#section-4
            var body_specifier: ?BodySpecifier = null;
            while (try readHeaderField(allocator, reader)) |header_field| {
                if (ascii.eqlIgnoreCase(header_field.name, "Content-Length")) {
                    // https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.2
                    if (body_specifier) |specifier|
                        if (specifier == .transfer_encoding)
                            return error.ContentLengthAndTransferEncoding;
                    body_specifier = .{ .content_length = try std.fmt.parseUnsigned(usize, header_field.value, 10) };
                } else if (ascii.eqlIgnoreCase(header_field.name, "Transfer-Encoding")) {
                    // https://datatracker.ietf.org/doc/html/rfc7230#section-3.3.1
                    if (ascii.eqlIgnoreCase(header_field.value, "chunked")) {
                        body_specifier = .{ .transfer_encoding = .chunked };
                    } else {
                        @panic("handle non-chunked transfer coding");
                    }
                }
                log.debug("header field: {s}: {s}", .{ header_field.name, header_field.value });
            }

            if (body_specifier) |specifier| {
                switch (specifier) {
                    .content_length => |length| {
                        const body = try allocator.alloc(u8, length);
                        var index: usize = 0;
                        while (index < length) : (index += 1)
                            body[index] = try reader.readByte();
                        return Response{ .status = status, .body = body };
                    },
                    .transfer_encoding => {
                        if (true) @panic("do we need this?");
                        const body = try readChunkedBody(allocator, reader);
                        log.debug("chunked body size {}", .{body.len});
                        return Response{ .status = status, .body = body };
                    },
                }
            } else {
                return Response{ .status = status, .body = null };
            }
        }

        fn readChunkedBody(allocator: mem.Allocator, reader: anytype) ![]const u8 {
            // https://datatracker.ietf.org/doc/html/rfc7230#section-4.1
            var body = std.ArrayList(u8).init(allocator);
            while (true) {
                const chunk_size = std.fmt.parseUnsigned(
                    usize,
                    try readUntilCRLF(allocator, reader),
                    16,
                ) catch @panic("is there chunk-ext after chunk-size?");

                if (chunk_size == 0)
                    break;

                log.debug("chunk size: {}", .{chunk_size});

                const chunk = try allocator.alloc(u8, chunk_size);
                var index: usize = 0;
                while (index < chunk_size) : (index += 1)
                    chunk[index] = try reader.readByte();

                try body.appendSlice(chunk);

                if (!mem.eql(u8, &try reader.readBytesNoEof(2), crlf))
                    return error.NoCRLF;
            }
            return body.toOwnedSlice();
        }

        fn readStatusLine(allocator: mem.Allocator, reader: anytype) !http.Status {
            // https://datatracker.ietf.org/doc/html/rfc7230#section-3.1.2
            const line = try readUntilCRLF(allocator, reader);
            var status_line_splitter = mem.split(u8, line, " ");
            const http_version = status_line_splitter.next() orelse return error.NoHTTPVersion;
            _ = http_version;
            const status_code = status_line_splitter.next() orelse return error.NoStatusCode;
            const reason_phrase = status_line_splitter.next() orelse return error.NoReasonPhrase;
            _ = reason_phrase;

            return std.meta.intToEnum(http.Status, try std.fmt.parseUnsigned(std.meta.Tag(http.Status), status_code, 10));
        }

        const HeaderField = struct {
            name: []const u8,
            value: []const u8,
        };

        fn readHeaderField(allocator: mem.Allocator, reader: anytype) !?HeaderField {
            // https://datatracker.ietf.org/doc/html/rfc7230#section-3.2
            const field = try readUntilCRLF(allocator, reader);
            if (field.len == 0)
                return null;
            var field_splitter = mem.split(u8, field, ":");
            return HeaderField{
                .name = field_splitter.next() orelse return error.NoHeaderFieldName,
                .value = mem.trim(u8, field_splitter.next() orelse return error.NoHeaderFieldValue, &whitespace),
            };
        }

        fn readMessageBody(allocator: mem.Allocator, reader: anytype) ![]const u8 {
            // https://datatracker.ietf.org/doc/html/rfc7230#section-3.3
            _ = allocator;
            _ = reader;
        }
    };

    fn readUntilCRLF(allocator: mem.Allocator, reader: anytype) ![]const u8 {
        var bytes = std.ArrayList(u8).init(allocator);

        while (true) {
            const first_byte = try reader.readByte();
            if (first_byte == '\r') {
                const second_byte = try reader.readByte();
                if (second_byte == '\n') {
                    return bytes.toOwnedSlice();
                }
                try bytes.append(second_byte);
            }
            try bytes.append(first_byte);
        }
    }

    pub fn sendRequest(self: Client, allocator: mem.Allocator, method: http.Method, path: []const u8, body: ?[]const u8) !Response {
        const request_string = try request.createMessage(self, allocator, @tagName(method), path, body);
        log.debug("sending request:\n{s}", .{request_string});
        try self.stream.writer().writeAll(request_string);

        log.debug("receiving response", .{});
        var buffered_reader = std.io.bufferedReader(self.stream.reader());
        const reader = buffered_reader.reader();
        return response.readMessage(allocator, reader);
    }
};
