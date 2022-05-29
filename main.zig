const std = @import("std");
const http = @import("http.zig");

pub fn main() !void {
    const client = try http.Client.init(std.testing.allocator, "example.com", .unencrypted);
    const response = try client.sendRequest(std.testing.allocator, .GET, "/", "hello");
    std.log.debug("response: {}: {s}", .{ response.status, response.body });
}
