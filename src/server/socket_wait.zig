//! Blocking mode's socket waits. Connection sockets are non-blocking even
//! in blocking mode, so a send never waits on a peer that stopped reading
//! (whichever thread sends: the application's broadcaster, say). A thread
//! that needs data waits here, on its socket and on its worker's Stop, so
//! shutdown wakes it without touching its socket: closing a socket another
//! thread is using is what Winsock forbids, and its handle can be reused at
//! once.
//!
//! Windows waits on WSAEventSelect events (which also make the socket
//! non-blocking); elsewhere on poll, with a pipe as the stop signal.

const std = @import("std");
const builtin = @import("builtin");

const posix = std.posix;
const windows = std.os.windows;
const ws2 = windows.ws2_32;

const is_windows = builtin.os.tag == .windows;

// WSAWaitForMultipleEvents' values, not declared by Zig 0.15.
const WSA_WAIT_FAILED: u32 = 0xFFFF_FFFF;
const WSA_WAIT_TIMEOUT: u32 = 0x102;
const WSA_INFINITE: u32 = 0xFFFF_FFFF;

/// A worker's stop signal. Set once, at shutdown, and never reset: every
/// wait from then on returns at once, including a connection's first.
pub const Stop = struct {
    stopping: std.atomic.Value(bool) = .init(false),
    /// Windows: a manual-reset event. Elsewhere: a pipe; signal writes a
    /// byte nobody reads, so poll reports it readable to every waiter.
    handle: if (is_windows) windows.HANDLE else [2]posix.fd_t,

    pub fn init() !Stop {
        if (is_windows) {
            const event = ws2.WSACreateEvent();
            if (@intFromPtr(event) == 0) return error.SystemResources;
            return .{ .handle = event };
        }
        return .{ .handle = try posix.pipe2(.{ .CLOEXEC = true }) };
    }

    /// Only once no thread can still wait on it.
    pub fn deinit(self: *Stop) void {
        if (is_windows) {
            _ = ws2.WSACloseEvent(self.handle);
        } else {
            posix.close(self.handle[0]);
            posix.close(self.handle[1]);
        }
    }

    /// Idempotent.
    pub fn signal(self: *Stop) void {
        if (self.stopping.swap(true, .acq_rel)) return;
        if (is_windows) {
            _ = ws2.WSASetEvent(self.handle);
        } else {
            _ = posix.write(self.handle[1], "s") catch {};
        }
    }

    pub fn isSet(self: *const Stop) bool {
        return self.stopping.load(.acquire);
    }
};

pub const Interest = enum { read, accept };

/// A socket's readiness, for the one thread that waits on it. Makes the
/// socket non-blocking.
pub const Waiter = struct {
    event: if (is_windows) windows.HANDLE else void,

    pub fn init(socket: posix.socket_t, interest: Interest) !Waiter {
        if (is_windows) {
            const event = ws2.WSACreateEvent();
            if (@intFromPtr(event) == 0) return error.SystemResources;
            const mask: i32 = switch (interest) {
                .read => ws2.FD_READ | ws2.FD_CLOSE,
                .accept => ws2.FD_ACCEPT,
            };
            if (ws2.WSAEventSelect(socket, event, mask) != 0) {
                _ = ws2.WSACloseEvent(event);
                return error.Unexpected;
            }
            return .{ .event = event };
        }
        const flags = try posix.fcntl(socket, posix.F.GETFL, 0);
        const nonblock: usize = @as(u32, @bitCast(posix.O{ .NONBLOCK = true }));
        _ = try posix.fcntl(socket, posix.F.SETFL, flags | nonblock);
        return .{ .event = {} };
    }

    /// After the socket is closed (closesocket ends the event selection).
    pub fn deinit(self: *Waiter) void {
        if (is_windows) _ = ws2.WSACloseEvent(self.event);
    }

    /// Wakes the waiting thread from another, while the socket is open:
    /// Windows signals the socket's event (a local shutdown doesn't wake
    /// a wait there); elsewhere the socket's read side is shut down, which
    /// poll reports as readable. Only the read side: shutting down the
    /// write side would send a FIN after whatever is buffered (and on macOS
    /// refuse the SO_LINGER that resets the connection instead).
    pub fn wake(self: *Waiter, socket: posix.socket_t) void {
        if (is_windows) {
            _ = ws2.WSASetEvent(self.event);
        } else {
            posix.shutdown(socket, .recv) catch {};
        }
    }

    /// Returns once the socket may be ready, it has been woken, or `stop`
    /// is set; error.Timeout after `timeout_ms`. May return with nothing to
    /// do: the caller tries again and checks its own flags.
    pub fn wait(self: *Waiter, socket: posix.socket_t, stop: *const Stop, timeout_ms: ?u32) !void {
        if (is_windows) {
            const events = [2]windows.HANDLE{ self.event, stop.handle };
            const rc = ws2.WSAWaitForMultipleEvents(2, &events, windows.FALSE, timeout_ms orelse WSA_INFINITE, windows.FALSE);
            if (rc == WSA_WAIT_FAILED) return windows.unexpectedWSAError(ws2.WSAGetLastError());
            if (rc == WSA_WAIT_TIMEOUT) return error.Timeout;
            // Resets the socket's event. A WSASetEvent this clears came
            // after its caller's flag store, which the caller checks next;
            // readiness this clears is re-reported by the next recv/accept.
            var network_events: ws2.WSANETWORKEVENTS = undefined;
            _ = ws2.WSAEnumNetworkEvents(socket, self.event, &network_events);
            return;
        }
        var fds = [2]posix.pollfd{
            .{ .fd = socket, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = stop.handle[0], .events = posix.POLL.IN, .revents = 0 },
        };
        const timeout: i32 = if (timeout_ms) |ms| @intCast(@min(ms, std.math.maxInt(i32))) else -1;
        if (try posix.poll(&fds, timeout) == 0) return error.Timeout;
    }
};

/// One non-blocking recv. 0 means the peer closed its side.
pub fn recv(socket: posix.socket_t, buf: []u8) !usize {
    if (is_windows) {
        const len: i32 = @intCast(@min(buf.len, std.math.maxInt(i32)));
        const rc = ws2.recv(socket, buf.ptr, len, 0);
        if (rc == ws2.SOCKET_ERROR) {
            return switch (ws2.WSAGetLastError()) {
                .WSAEWOULDBLOCK => error.WouldBlock,
                .WSAECONNRESET, .WSAECONNABORTED, .WSAENETRESET => error.ConnectionResetByPeer,
                .WSAETIMEDOUT => error.ConnectionTimedOut,
                .WSAESHUTDOWN => error.Closed,
                else => error.Unexpected,
            };
        }
        return @intCast(rc);
    }
    return posix.read(socket, buf);
}

/// Closes a socket. On Windows that is closesocket: posix.close there is
/// CloseHandle, which Microsoft says must not be used on a socket (it skips
/// Winsock's own cleanup, SO_LINGER included). An abortive close resets the
/// connection instead of leaving the system to deliver what is still
/// buffered to a peer that may never read it.
pub fn closeSocket(socket: posix.socket_t, abortive: bool) void {
    if (abortive) {
        // Through the raw call, result ignored: on a socket already shut
        // down or reset, macOS fails this with EINVAL, which Zig's
        // posix.setsockopt treats as unreachable. A plain close is then
        // the best there is.
        if (is_windows) {
            const linger = ws2.linger{ .onoff = 1, .linger = 0 };
            _ = ws2.setsockopt(socket, ws2.SOL.SOCKET, ws2.SO.LINGER, std.mem.asBytes(&linger), @sizeOf(ws2.linger));
        } else {
            const linger = extern struct { onoff: c_int, linger: c_int }{ .onoff = 1, .linger = 0 };
            _ = posix.system.setsockopt(socket, posix.SOL.SOCKET, posix.SO.LINGER, std.mem.asBytes(&linger), @sizeOf(@TypeOf(linger)));
        }
    }
    if (is_windows) {
        windows.closesocket(socket) catch {};
    } else {
        posix.close(socket);
    }
}
