const std = @import("std");
const builtin = @import("builtin");
const proto = @import("../proto.zig");
const buffer = @import("../buffer.zig");

const net = std.net;
const posix = std.posix;
const Thread = std.Thread;
const Allocator = std.mem.Allocator;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;

const log = std.log.scoped(.websocket);

// Windows-compatible socket option constants.
// std.posix.SOL/SO resolve to empty structs on Windows.
const SOL_SOCKET: i32 = if (builtin.os.tag == .windows)
    @intCast(std.os.windows.ws2_32.SOL.SOCKET)
else
    posix.SOL.SOCKET;

const SO_RCVTIMEO: u32 = if (builtin.os.tag == .windows)
    @intCast(std.os.windows.ws2_32.SO.RCVTIMEO)
else
    posix.SO.RCVTIMEO;

const SO_SNDTIMEO: u32 = if (builtin.os.tag == .windows)
    @intCast(std.os.windows.ws2_32.SO.SNDTIMEO)
else
    posix.SO.SNDTIMEO;

// SO_RCVTIMEO/SO_SNDTIMEO's value: a timeval, except on Windows, where it's
// a DWORD of milliseconds (a timeval there reads as its seconds field in
// milliseconds: 5 s would be 5 ms). 0 means no timeout.
const SocketTimeout = if (builtin.os.tag == .windows) [4]u8 else [@sizeOf(posix.timeval)]u8;

fn socketTimeout(sec: u32) SocketTimeout {
    if (builtin.os.tag == .windows) return std.mem.toBytes(@as(u32, sec *| 1000));
    return std.mem.toBytes(posix.timeval{ .sec = @intCast(sec), .usec = 0 });
}

/// What a send to a connection's socket can fail with (Conn.sendSome).
const SendError = error{
    WouldBlock,
    BrokenPipe,
    ConnectionResetByPeer,
    SocketNotConnected,
    SystemResources,
    NotOpenForWriting,
    FileDescriptorNotASocket,
    Unexpected,
};

/// setsockopt on a connection's socket. Darwin fails any setsockopt on a
/// socket its peer has already reset (one shut down both ways) with EINVAL,
/// which posix.setsockopt treats as unreachable: a client resetting at the
/// wrong moment would panic the process. Here that is
/// error.ConnectionResetByPeer, and EBADF and ENOTSOCK are errors too.
/// Windows goes through posix.setsockopt, which has no such case.
fn setConnectionOption(socket: posix.socket_t, level: i32, name: u32, value: []const u8) !void {
    if (comptime builtin.os.tag == .windows) return posix.setsockopt(socket, level, name, value);
    switch (posix.errno(posix.system.setsockopt(socket, level, name, value.ptr, @intCast(value.len)))) {
        .SUCCESS => {},
        .INVAL => return error.ConnectionResetByPeer,
        .BADF => return error.NotOpenForWriting,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .NOMEM, .NOBUFS => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
}

/// Darwin: a write to a dead peer on this socket fails with EPIPE instead of
/// raising SIGPIPE, whatever call makes it. Conn's sends already pass
/// MSG_NOSIGNAL; this also covers any write that doesn't, and kernels that
/// ignore the flag. Best effort for the same reason. Other systems have no
/// such option (Linux) or no SIGPIPE (Windows).
fn suppressSigpipe(socket: posix.socket_t) void {
    if (comptime !builtin.os.tag.isDarwin()) return;
    setConnectionOption(socket, posix.SOL.SOCKET, posix.SO.NOSIGPIPE, std.mem.asBytes(&@as(c_int, 1))) catch |err| switch (err) {
        // Already reset: the next read ends the connection.
        error.ConnectionResetByPeer => {},
        else => log.warn("failed to set SO_NOSIGPIPE: {}", .{err}),
    };
}

const SO_SNDBUF: u32 = if (builtin.os.tag == .windows)
    @intCast(std.os.windows.ws2_32.SO.SNDBUF)
else
    posix.SO.SNDBUF;

const SO_REUSEADDR: u32 = if (builtin.os.tag == .windows)
    @intCast(std.os.windows.ws2_32.SO.REUSEADDR)
else
    posix.SO.REUSEADDR;

/// Closes a socket. On Windows that is closesocket: posix.close there is
/// CloseHandle, which Microsoft says must not be used on a socket (it skips
/// Winsock's own cleanup, SO_LINGER included).
fn closeSocketHandle(socket: posix.socket_t) void {
    socket_wait.closeSocket(socket, false);
}

const OpCode = proto.OpCode;
const Reader = proto.Reader;
const Message = proto.Message;
pub const Handshake = @import("handshake.zig").Handshake;
const Compression = @import("../websocket.zig").Compression;
const FallbackAllocator = @import("fallback_allocator.zig").FallbackAllocator;
const socket_wait = @import("socket_wait.zig");

const DEFAULT_MAX_CONN = 16_384;
const DEFAULT_BUFFER_SIZE = 2048;
const DEFAULT_MAX_MESSAGE_SIZE = 65_536;

const EMPTY_PONG = ([2]u8{ @intFromEnum(OpCode.pong), 0 })[0..];
// CLOSE, 2 length, code
const CLOSE_NORMAL = ([_]u8{ @intFromEnum(OpCode.close), 2, 3, 232 })[0..]; // code: 1000
const CLOSE_PROTOCOL_ERROR = ([_]u8{ @intFromEnum(OpCode.close), 2, 3, 234 })[0..]; //code: 1002

const force_blocking: bool = blk: {
    const build = @import("build");
    if (@hasDecl(build, "websocket_blocking")) {
        break :blk build.websocket_blocking;
    }
    break :blk false;
};

pub fn blockingMode() bool {
    if (force_blocking) {
        return true;
    }
    return switch (builtin.os.tag) {
        .linux, .macos, .ios, .tvos, .watchos, .freebsd, .netbsd, .dragonfly, .openbsd => false,
        else => true,
    };
}

pub const Config = struct {
    port: u16 = 9882,
    address: []const u8 = "127.0.0.1",
    unix_path: ?[]const u8 = null,

    worker_count: ?u8 = null,

    max_conn: ?usize = null,
    max_message_size: ?usize = null,

    handshake: Config.Handshake = .{},
    thread_pool: ThreadPool = .{},
    buffers: Config.Buffers = .{},
    compression: ?Compression = null,

    pub const ThreadPool = struct {
        count: ?u16 = null,
        backlog: ?u32 = null,
        buffer_size: ?usize = null,
    };

    pub const Handshake = struct {
        timeout: u32 = 10,
        max_size: ?u16 = null,
        max_headers: ?u16 = null,
        max_res_headers: ?u16 = null,
        count: ?u16 = null,
    };

    pub const Buffers = struct {
        small_size: ?usize = null,
        small_pool: ?usize = null,
        large_size: ?usize = null,
        large_pool: ?u16 = null,
    };

    fn workerCount(self: *const Config) usize {
        if (comptime blockingMode()) {
            return 1;
        }
        return self.worker_count orelse 1;
    }
};

pub fn Server(comptime H: type) type {
    return struct {
        config: Config,
        allocator: Allocator,

        _state: WorkerState,
        _signals: []posix.fd_t,
        /// Blocking mode: the running worker's stop signal, which stop()
        /// sets. Guarded by _mut.
        _stop: ?*socket_wait.Stop = null,
        /// listen is serving; stop() waits until it isn't. Guarded by _mut.
        _running: bool = false,
        _mut: Thread.Mutex,
        _cond: Thread.Condition,

        const Self = @This();

        pub fn init(allocator: Allocator, config: Config) !Self {
            if (blockingMode()) {
                if (config.buffers.small_pool) |p| {
                    if (p > 1) {
                        log.warn("blockingMode() cannot utilize a small buffer pool, using per-connection buffer instead", .{});
                    }
                }
            }

            if (config.compression != null) {
                log.err("Compression is disabled as part of the 0.15 upgrade. I do hope to re-enable it soon.", .{});
                return error.InvalidConfiguraion;
            }

            const signals = try allocator.alloc(posix.fd_t, config.workerCount());
            errdefer allocator.free(signals);

            var state = try WorkerState.init(allocator, config);
            errdefer state.deinit();

            return .{
                ._mut = .{},
                ._cond = .{},
                ._state = state,
                ._signals = signals,
                .config = config,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self._state.deinit();
            self.allocator.free(self._signals);
        }

        pub fn listenInNewThread(self: *Self, ctx: anytype) !Thread {
            self._mut.lock();
            defer self._mut.unlock();
            const thrd = try Thread.spawn(.{}, Self.listen, .{ self, ctx });

            // we don't return until listen() signals us that the server is up
            self._cond.wait(&self._mut);
            return thrd;
        }

        pub fn listen(self: *Self, ctx: anytype) !void {
            self._mut.lock();
            errdefer {
                self._cond.signal();
                self._mut.unlock();
            }

            const config = &self.config;

            var no_delay = true;
            const address = blk: {
                if (config.unix_path) |unix_path| {
                    if (comptime std.net.has_unix_sockets == false) {
                        return error.UnixPathNotSupported;
                    }
                    no_delay = false;
                    std.fs.deleteFileAbsolute(unix_path) catch {};
                    break :blk try net.Address.initUnix(unix_path);
                } else {
                    const listen_port = config.port;
                    const listen_address = config.address;
                    break :blk try net.Address.parseIp(listen_address, listen_port);
                }
            };

            const socket = blk: {
                var sock_flags: u32 = posix.SOCK.STREAM | posix.SOCK.CLOEXEC;
                if (blockingMode() == false) sock_flags |= posix.SOCK.NONBLOCK;

                const socket_proto = if (address.any.family == posix.AF.UNIX) @as(u32, 0) else posix.IPPROTO.TCP;
                break :blk try posix.socket(address.any.family, sock_flags, socket_proto);
            };

            if (no_delay) {
                // TODO: Broken on darwin:
                // https://github.com/ziglang/zig/issues/17260
                // if (@hasDecl(os.TCP, "NODELAY")) {
                //  try os.setsockopt(socket.sockfd.?, os.IPPROTO.TCP, os.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1)));
                // }
                try posix.setsockopt(socket, posix.IPPROTO.TCP, 1, &std.mem.toBytes(@as(c_int, 1)));
            }

            if (@hasDecl(posix.SO, "REUSEPORT_LB")) {
                try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEPORT_LB, &std.mem.toBytes(@as(c_int, 1)));
            } else if (@hasDecl(posix.SO, "REUSEPORT")) {
                try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1)));
            } else {
                try posix.setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
            }

            {
                const socklen = address.getOsSockLen();
                try posix.bind(socket, &address.any, socklen);
                try posix.listen(socket, 1024); // kernel backlog
            }

            const C = @TypeOf(ctx);

            if (comptime blockingMode()) {
                errdefer closeSocketHandle(socket);
                var w = try Blocking(H).init(self.allocator, &self._state);
                defer w.deinit();

                // run owns the listener from here, and closes it.
                const thrd = try std.Thread.spawn(.{}, Blocking(H).run, .{ &w, socket, ctx });
                log.info("starting blocking worker to listen on {f}", .{address});

                // incase listenInNewThread was used and is waiting for us to start
                self._cond.signal();

                // this is what stop() signals
                self._stop = &w.stop;
                self._running = true;
                self._mut.unlock();
                thrd.join();
                self._mut.lock();
                self._stop = null;
                self._mut.unlock();
            } else {
                defer posix.close(socket);
                const W = NonBlocking(H, C);

                const allocator = self.allocator;

                var signals = self._signals;
                const worker_count = signals.len;
                const threads = try allocator.alloc(Thread, worker_count);
                const workers = try allocator.alloc(W, worker_count);

                var started: usize = 0;

                errdefer for (0..started) |i| {
                    // on success, these will be closed by a call to stop();
                    posix.close(signals[i]);
                };

                defer {
                    for (0..started) |i| {
                        workers[i].deinit();
                    }
                    allocator.free(threads);
                    allocator.free(workers);
                }

                for (0..worker_count) |i| {
                    const pipe = try posix.pipe2(.{ .NONBLOCK = true });
                    errdefer posix.close(pipe[1]);

                    workers[i] = try W.init(self.allocator, &self._state, ctx);
                    errdefer workers[i].deinit();

                    threads[i] = try Thread.spawn(.{}, W.run, .{ &workers[i], socket, pipe[0] });

                    signals[i] = pipe[1];
                    started += 1;
                }

                log.info("starting nonblocking worker to listen on {f}", .{address});

                // in case startInNewThread is waiting
                self._cond.signal();

                self._running = true;
                self._mut.unlock();

                for (threads) |thrd| {
                    thrd.join();
                }
            }
            self._mut.lock();
            defer self._mut.unlock();
            self._running = false;
            self._cond.broadcast();
        }

        /// Returns once listen has stopped serving (at once if it isn't:
        /// its worker may have ended on an error).
        pub fn stop(self: *Self) void {
            self._mut.lock();
            defer self._mut.unlock();
            if (!self._running) return;
            if (comptime blockingMode()) {
                // The worker's accept loop and connections wait on this;
                // run closes the listener once they are done.
                if (self._stop) |s| s.signal();
            } else {
                for (self._signals) |s| posix.close(s);
            }
            while (self._running) self._cond.wait(&self._mut);
        }
    };
}

// This is our Blocking worker. It's very different than NonBlocking and much simpler.
// Each connection has a thread, which alone reads its socket and alone closes
// it. The socket is non-blocking all the same (see socket_wait.zig): writes
// from any thread never wait on the peer, and the thread waits for data on
// the socket and on the worker's stop signal, so shutdown never has to
// touch a socket to end a connection.
pub fn Blocking(comptime H: type) type {
    return struct {
        allocator: Allocator,
        handshake_timeout_sec: u32,
        connection_buffer_size: usize,
        conn_manager: ConnManager(H, false),
        handshake_pool: *Handshake.Pool,
        buffer_provider: *buffer.Provider,
        compression: ?Compression,
        stop: socket_wait.Stop,
        // A standalone server's connection threads still running (run
        // detaches them), so run can wait for them before the worker is
        // freed. Guarded by threads_mut.
        threads: usize = 0,
        threads_mut: Thread.Mutex = .{},
        threads_done: Thread.Condition = .{},

        const Self = @This();

        pub fn init(allocator: Allocator, state: *WorkerState) !Self {
            const config = &state.config;

            var conn_manager = try ConnManager(H, false).init(allocator, config.compression);
            errdefer conn_manager.deinit();

            return .{
                .conn_manager = conn_manager,
                .allocator = allocator,
                .compression = config.compression,
                .handshake_pool = state.handshake_pool,
                .buffer_provider = &state.buffer_provider,
                .handshake_timeout_sec = config.handshake.timeout,
                .connection_buffer_size = config.buffers.small_size orelse DEFAULT_BUFFER_SIZE,
                .stop = try socket_wait.Stop.init(),
            };
        }

        /// Once no connection's thread is running.
        pub fn deinit(self: *Self) void {
            self.conn_manager.deinit();
            self.stop.deinit();
        }

        pub fn run(self: *Self, listener: posix.socket_t, ctx: anytype) void {
            defer {
                self.shutdown();
                self.waitForConnectionThreads();
            }
            var waiter = socket_wait.Waiter.init(listener, .accept) catch |err| {
                log.err("failed to wait on the listening socket: {}", .{err});
                closeSocketHandle(listener);
                return;
            };
            // Closed here, on the thread accepting on it; then its event.
            defer waiter.deinit();
            defer closeSocketHandle(listener);

            while (true) {
                if (self.stop.isSet()) {
                    log.info("received shutdown signal", .{});
                    return;
                }
                var address: net.Address = undefined;
                var address_len: posix.socklen_t = @sizeOf(net.Address);
                const socket = posix.accept(listener, &address.any, &address_len, posix.SOCK.CLOEXEC) catch |err| switch (err) {
                    error.WouldBlock => {
                        waiter.wait(listener, &self.stop, null) catch |wait_err| {
                            log.err("failed to wait for connections: {}", .{wait_err});
                            return;
                        };
                        continue;
                    },
                    // A client that went away before we got to it.
                    error.ConnectionAborted, error.ConnectionResetByPeer => continue,
                    error.SocketNotListening => {
                        log.err("failed to accept socket: {}", .{err});
                        return;
                    },
                    else => {
                        // Out of descriptors or buffers, say: likely to
                        // pass, so try again shortly (or stop).
                        log.err("failed to accept socket: {}", .{err});
                        waiter.wait(listener, &self.stop, 100) catch |wait_err| switch (wait_err) {
                            error.Timeout => {},
                            else => {
                                log.err("failed to wait for connections: {}", .{wait_err});
                                return;
                            },
                        };
                        continue;
                    },
                };
                log.debug("({f}) connected", .{address});
                suppressSigpipe(socket);

                self.threads_mut.lock();
                self.threads += 1;
                self.threads_mut.unlock();
                const thread = std.Thread.spawn(.{}, Self.handleConnection, .{ self, socket, address, ctx }) catch |err| {
                    self.connectionThreadDone();
                    closeSocketHandle(socket);
                    log.err("({f}) failed to spawn connection thread: {}", .{ address, err });
                    continue;
                };
                thread.detach();
            }
        }

        fn connectionThreadDone(self: *Self) void {
            self.threads_mut.lock();
            defer self.threads_mut.unlock();
            self.threads -= 1;
            if (self.threads == 0) self.threads_done.broadcast();
        }

        // Every wait in a connection's thread returns once stop is set, so
        // this only waits for handlers to return.
        fn waitForConnectionThreads(self: *Self) void {
            self.threads_mut.lock();
            defer self.threads_mut.unlock();
            while (self.threads > 0) self.threads_done.wait(&self.threads_mut);
        }

        // Called in a thread started above in listen.
        // Wrapper around _handleConnection so that we can handle erros
        fn handleConnection(self: *Self, socket: posix.socket_t, address: net.Address, ctx: anytype) void {
            defer self.connectionThreadDone();
            self._handleConnection(socket, address, ctx) catch |err| {
                log.err("({f}) uncaught error in connection handler: {}", .{ address, err });
            };
        }

        fn _handleConnection(self: *Self, socket: posix.socket_t, address: net.Address, ctx: anytype) !void {
            const conn_manager = &self.conn_manager;
            const hc = try conn_manager.create(socket, address, timestamp());

            {
                // Do our handshake
                errdefer self.cleanupConn(hc);
                hc.conn.blocking.handshake_deadline_ms = std.time.milliTimestamp() + @as(i64, self.handshake_timeout_sec) * std.time.ms_per_s;

                while (true) {
                    const compression, const ok = handleHandshake(H, self, hc, ctx);
                    if (ok == false) {
                        self.cleanupConn(hc);
                        return;
                    }
                    if (hc.handler != null) {
                        // if we have a handler, the our handshake completed
                        if (compression) {
                            try conn_manager.setupCompression(hc);
                        }
                        break;
                    }
                }
            }

            return self.readLoop(hc);
        }

        // The readloop is extracted from _handleConnection so that it can be called
        // directly when integrating with an http server
        pub fn readLoop(self: *Self, hc: *HandlerConn(H)) !void {
            defer self.cleanupConn(hc);

            // In BlockingMode, we always assign a reader for the duration of the connection
            // In scenarios where client rarely send data, this is going to use up an unecessary amount
            // of memory, but unlike nonblocking mode, we can't initialize the buffer just-in-time.
            const reader_buf = try self.allocator.alloc(u8, self.connection_buffer_size);
            defer self.allocator.free(reader_buf);

            hc.reader = Reader.init(reader_buf, self.buffer_provider, hc.compression);

            while (true) {
                if (handleClientData(H, hc, self.allocator, undefined, &self.stop) == false) {
                    break;
                }
                // A peer that keeps sending never waits, which is where
                // reads see the stop signal.
                if (self.stop.isSet()) break;
            }
        }

        // The handler first: until its close() runs, the application may
        // still write to the conn from other threads (a broadcaster). Then
        // the socket, on this, its connection's thread.
        fn cleanupConn(self: *Self, hc: *HandlerConn(H)) void {
            self.conn_manager.closeHandler(hc);
            hc.conn.release();
            self.conn_manager.cleanup(hc);
        }

        /// Ends every connection: each one's thread sees the stop signal at
        /// its next wait (or after the message it is handling) and closes
        /// its connection. Doesn't wait for them; idempotent.
        fn shutdown(self: *Self) void {
            self.stop.signal();
        }
    };
}

fn NonBlocking(comptime H: type, comptime C: type) type {
    return struct {
        ctx: C,

        max_conn: usize,

        // KQueue or Epoll, depending on the platform
        loop: Loop,
        thread_pool: *ThreadPool,

        handshake_timeout: u32,
        handshake_pool: *Handshake.Pool,
        base: NonBlockingBase(H, true),
        compression: ?Compression,

        const Self = @This();
        const ThreadPool = @import("thread_pool.zig").ThreadPool(Self.dataAvailable);

        pub fn init(allocator: Allocator, state: *WorkerState, ctx: C) !Self {
            var base = try NonBlockingBase(H, true).init(allocator, state);
            errdefer base.deinit();

            const loop = try Loop.init();
            errdefer loop.deinit();

            const config = &state.config;
            var thread_pool = try ThreadPool.init(allocator, .{
                .count = config.thread_pool.count orelse 4,
                .backlog = config.thread_pool.backlog orelse 500,
                .buffer_size = config.thread_pool.buffer_size orelse if (needsAllocator(H)) 32_768 else 0,
            });
            errdefer thread_pool.deinit();

            return .{
                .ctx = ctx,
                .loop = loop,
                .base = base,
                .thread_pool = thread_pool,
                .compression = config.compression,
                .handshake_pool = state.handshake_pool,
                .handshake_timeout = state.config.handshake.timeout,
                .max_conn = config.max_conn orelse DEFAULT_MAX_CONN,
            };
        }

        pub fn deinit(self: *Self) void {
            self.loop.deinit();
            self.base.deinit();
            self.thread_pool.deinit();
        }

        fn run(self: *Self, listener: posix.socket_t, signal: posix.fd_t) void {
            self.loop.monitorAccept(listener) catch |err| {
                log.err("failed to add monitor to listening socket: {}", .{err});
                return;
            };

            self.loop.monitorSignal(signal) catch |err| {
                log.err("failed to add monitor to signal pipe: {}", .{err});
                return;
            };

            const thread_pool = self.thread_pool;
            const conn_manager = &self.base.conn_manager;
            const handshake_timeout = self.handshake_timeout;

            var now = timestamp();
            var oldest_pending_start_time: ?u32 = null;
            while (true) {
                const handshake_cutoff = now - handshake_timeout;
                const timeout = self.prepareToWait(handshake_cutoff) orelse blk: {
                    if (oldest_pending_start_time) |started| {
                        break :blk if (started < handshake_cutoff) 1 else @as(i32, @intCast(started - handshake_cutoff));
                    }
                    break :blk null;
                };

                var it = self.loop.wait(timeout) catch |err| {
                    log.err("failed to wait on events: {}", .{err});
                    std.Thread.sleep(std.time.ns_per_s);
                    continue;
                };

                now = timestamp();
                oldest_pending_start_time = null;
                while (it.next()) |data| {
                    if (data == 0) {
                        self.accept(listener, now) catch |err| {
                            log.err("accept error: {}", .{err});
                            std.Thread.sleep(std.time.ns_per_ms);
                        };
                        continue;
                    }

                    if (data == 1) {
                        self.base.shutdown();
                        return;
                    }

                    const hc: *HandlerConn(H) = @ptrFromInt(data);
                    if (hc.state == .handshake) {
                        // we need to get this out of the pending list, so that it doesn't
                        // cause a timeout while we're processing it.
                        // But we stll need to care about its timeout.
                        if (oldest_pending_start_time) |s| {
                            oldest_pending_start_time = @min(hc.conn.started, s);
                        } else {
                            oldest_pending_start_time = hc.conn.started;
                        }
                        conn_manager.activate(hc);
                    }
                    thread_pool.spawn(.{ self, hc });
                }
            }
        }

        // Enforces timeouts, and returns when the next timeout should be checked.
        fn prepareToWait(self: *Self, cutoff: u32) ?i32 {
            const cm = &self.base.conn_manager;

            // always ordered from oldest to newest, so once we find a conneciton
            // that isn't timed out, we can stop
            cm.lock.lock();
            defer cm.lock.unlock();

            var next_conn = cm.pending.head;
            while (next_conn) |hc| {
                const conn = &hc.conn;
                const started = conn.started;
                if (started > cutoff) {
                    // This is the first connection which hasn't timed out
                    // return the time until it times out.
                    return @intCast(started - cutoff);
                }

                next_conn = hc.next;

                // this connection has timed out. Don't use self.cleanup since there's
                // a bunch of stuff we can assume here..like there's no handler or reader
                conn.closeSocket();
                log.debug("({f}) handshake timeout", .{conn.address});
                if (hc.handshake) |h| {
                    h.release();
                }
                cm.pending.remove(hc);
                cm.pool.destroy(hc);
            }
            return null;
        }

        fn accept(self: *Self, listener: posix.fd_t, now: u32) !void {
            const max_conn = self.max_conn;
            const conn_manager = &self.base.conn_manager;

            while (conn_manager.count() < max_conn) {
                var address: net.Address = undefined;
                var address_len: posix.socklen_t = @sizeOf(net.Address);

                const socket = posix.accept(listener, &address.any, &address_len, posix.SOCK.CLOEXEC) catch |err| {
                    // When available, we use SO_REUSEPORT_LB or SO_REUSEPORT, so WouldBlock
                    // should not be possible in those cases, but if it isn't available
                    // this error should be ignored as it means another thread picked it up.
                    return if (err == error.WouldBlock) {} else err;
                };

                log.debug("({f}) connected", .{address});
                suppressSigpipe(socket);

                {
                    errdefer posix.close(socket);
                    // socket is _probably_ in NONBLOCKING mode (it inherits
                    // the flag from the listening socket).
                    const flags = try posix.fcntl(socket, posix.F.GETFL, 0);
                    const nonblocking = @as(u32, @bitCast(posix.O{ .NONBLOCK = true }));
                    if (flags & nonblocking == nonblocking) {
                        // Yup, it's in nonblocking mode. Disable that flag to
                        // put it in blocking mode.
                        _ = try posix.fcntl(socket, posix.F.SETFL, flags & ~nonblocking);
                    }
                }
                const hc = try self.base.newConn(socket, address, now);
                self.loop.monitorRead(hc, false) catch |err| {
                    self.base.cleanupConn(hc);
                    return err;
                };
            }
        }

        // Called in a thread-pool thread/
        // !! Access to self has to be synchronized !!
        // There can only be 1 dataAvailable executing per HC at any given time.
        // Access to HC *should not* need to be synchronized. Access to hc.conn
        // needs to be synchronized once &hc.conn is passed to the handler during
        // handshake (Conn is self-synchronized).
        // Shutdown throws a wrench in our synchronization model, since we could
        // be shutting down while we're processing data...but hopefully the way we
        // shutdown (by waiting for all the thread pools threads to end) solves this.
        // Else, we'll need to throw a bunch of locking around HC just to handle shutdown.
        fn dataAvailable(self: *Self, hc: *HandlerConn(H), thread_buf: []u8) void {
            var success = false;
            {
                hc.cleanup.lock();
                defer hc.cleanup.unlock();
                if (hc.handler == null) {
                    success = self.dataForHandshake(hc) catch |err| blk: {
                        log.err("({f}) error processing handshake: {}", .{ hc.conn.address, err });
                        break :blk false;
                    };
                } else {
                    success = self.base.dataAvailable(hc, thread_buf);
                }
            }

            var conn = &hc.conn;
            var closed: bool = undefined;
            if (success == false) {
                conn.closeSocket();
                closed = true;
            } else {
                closed = conn.isClosed();
            }

            if (closed) {
                self.base.cleanupConn(hc);
            } else {
                self.loop.monitorRead(hc, true) catch |err| {
                    log.debug("({f}) failed to add read event monitor: {}", .{ conn.address, err });
                    conn.closeSocket();
                    self.base.cleanupConn(hc);
                };
            }
        }

        fn dataForHandshake(self: *Self, hc: *HandlerConn(H)) !bool {
            var conn_manager = &self.base.conn_manager;
            const compression, const ok = handleHandshake(H, self, hc, self.ctx);
            if (ok == false) {
                return false;
            }

            if (hc.handler == null) {
                // still don't have a handshake
                conn_manager.inactive(hc);
            }

            if (compression) {
                try conn_manager.setupCompression(hc);
            }
            return true;
        }
    };
}

fn NonBlockingBase(comptime H: type, comptime MANAGE_HS: bool) type {
    return struct {
        allocator: Allocator,

        buffer_provider: *buffer.Provider,

        // App can configure the use of a "small" buffer pool. This is the difference
        // between assigning a buffer to the connection just-in-time per message, or always
        small_buffer_pool: ?buffer.Pool,
        connection_buffer_size: usize,

        conn_manager: ConnManager(H, MANAGE_HS),

        const Self = @This();

        fn init(allocator: Allocator, state: *WorkerState) !Self {
            const config = &state.config;

            var conn_manager = try ConnManager(H, MANAGE_HS).init(allocator, config.compression);
            errdefer conn_manager.deinit();

            const connection_buffer_size = config.buffers.small_size orelse DEFAULT_BUFFER_SIZE;
            var small_buffer_pool: ?buffer.Pool = null;
            if (config.buffers.small_pool) |pool_count| {
                small_buffer_pool = try buffer.Pool.init(allocator, pool_count, connection_buffer_size);
            }

            errdefer if (small_buffer_pool) |sbp| {
                sbp.deinit();
            };

            return .{
                .allocator = allocator,
                .conn_manager = conn_manager,
                .small_buffer_pool = small_buffer_pool,
                .buffer_provider = &state.buffer_provider,
                .connection_buffer_size = connection_buffer_size,
            };
        }

        fn deinit(self: *Self) void {
            self.conn_manager.deinit();
            if (self.small_buffer_pool) |*sbp| {
                sbp.deinit();
            }
        }

        fn newConn(self: *Self, socket: posix.socket_t, address: net.Address, time: u32) !*HandlerConn(H) {
            return self.conn_manager.create(socket, address, time);
        }

        pub fn dataAvailable(self: *Self, hc: *HandlerConn(H), thread_buf: []u8) bool {
            return self._dataAvailable(hc, thread_buf) catch |err| {
                log.err("({f}) error processing client message: {}", .{ hc.conn.address, err });
                return false;
            };
        }

        fn _dataAvailable(self: *Self, hc: *HandlerConn(H), thread_buf: []u8) !bool {
            if (hc.reader == null) {
                const reader_buf = if (self.small_buffer_pool) |*sbp| try sbp.acquireOrCreate() else try self.allocator.alloc(u8, self.connection_buffer_size);
                hc.reader = Reader.init(reader_buf, self.buffer_provider, hc.compression);
            }
            const reader = &hc.reader.?;

            var fba = FixedBufferAllocator.init(thread_buf);
            const ok = handleClientData(H, hc, self.allocator, &fba, {});

            if (self.small_buffer_pool) |*sbp| {
                if (reader.isEmpty()) {
                    sbp.release(reader.static);
                    hc.reader = null;
                }
            }

            return ok;
        }

        fn cleanupConn(self: *Self, hc: *HandlerConn(H)) void {
            {
                hc.cleanup.lock();
                defer hc.cleanup.unlock();
                if (hc.reader) |*reader| {
                    if (self.small_buffer_pool) |*sbp| {
                        sbp.release(reader.static);
                    } else {
                        self.allocator.free(reader.static);
                    }
                    hc.reader = null;
                }
            }
            self.conn_manager.cleanup(hc);
        }

        fn shutdown(self: *Self) void {
            log.info("received shutdown signal", .{});
            self.conn_manager.shutdown(self);
        }

        // called for each hc when shutting down: closes its handler and its
        // socket. Under hc.cleanup, so not while ConnManager.cleanup is
        // closing the handler, nor while a standalone NonBlocking worker's
        // pool thread is in it (its dataAvailable holds hc.cleanup). httpz
        // runs handlers without hc.cleanup, and stops its pool before this.
        fn shutdownCleanup(self: *Self, hc: *HandlerConn(H)) void {
            {
                hc.cleanup.lock();
                defer hc.cleanup.unlock();
                if (hc.handler) |*h| {
                    if (comptime std.meta.hasFn(H, "close")) {
                        h.close();
                    }
                    hc.handler = null;
                }
                if (hc.reader) |*reader| {
                    if (self.small_buffer_pool == null) {
                        self.allocator.free(reader.static);
                    }
                    hc.reader = null;
                }
            }
            hc.conn.closeSocket();
        }
    };
}

const Loop = switch (@import("builtin").os.tag) {
    .macos, .ios, .tvos, .watchos, .freebsd, .netbsd, .dragonfly, .openbsd => KQueue,
    .linux => EPoll,
    else => unreachable,
};

const KQueue = struct {
    q: i32,
    change_count: usize,
    change_buffer: [16]Kevent,
    event_list: [64]Kevent,

    const Kevent = posix.Kevent;

    fn init() !KQueue {
        return .{
            .q = try posix.kqueue(),
            .change_count = 0,
            .change_buffer = undefined,
            .event_list = undefined,
        };
    }

    fn deinit(self: KQueue) void {
        posix.close(self.q);
    }

    fn monitorAccept(self: *KQueue, fd: c_int) !void {
        try self.change(fd, 0, posix.system.EVFILT.READ, posix.system.EV.ADD);
    }

    fn monitorSignal(self: *KQueue, fd: c_int) !void {
        try self.change(fd, 1, posix.system.EVFILT.READ, posix.system.EV.ADD);
    }

    // Normally, we add the socket in the worker thread with rearm == false.
    // Because this is a DISPATCH, it'll only fire once until we rearm it which
    // we do by re-enabling it with rearm == true.
    // However, notice that the rearm path also has the EV.ADD flag. From the above
    // description, this should not be necessary.
    // But monitorRead where rearm == true is also used by our generic ServerLoop when
    // taking over a connection (say from httpz). Hence, we need the EV.ADD flag too.
    fn monitorRead(self: *KQueue, hc: anytype, comptime rearm: bool) !void {
        if (rearm == false) {
            return self.change(hc.socket, @intFromPtr(hc), posix.system.EVFILT.READ, posix.system.EV.ADD | posix.system.EV.ENABLE | posix.system.EV.DISPATCH);
        }
        const event = Kevent{
            .ident = @intCast(hc.socket),
            .filter = posix.system.EVFILT.READ,
            .flags = posix.system.EV.ADD | posix.system.EV.ENABLE | posix.system.EV.DISPATCH,
            .fflags = 0,
            .data = 0,
            .udata = @intFromPtr(hc),
        };
        _ = try posix.kevent(self.q, &.{event}, &[_]Kevent{}, null);
    }

    fn change(self: *KQueue, fd: posix.fd_t, data: usize, filter: i16, flags: u16) !void {
        var change_count = self.change_count;
        var change_buffer = &self.change_buffer;

        if (change_count == change_buffer.len) {
            // calling this with an empty event_list will return immediate
            _ = try posix.kevent(self.q, change_buffer, &[_]Kevent{}, null);
            change_count = 0;
        }
        change_buffer[change_count] = .{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = data,
        };
        self.change_count = change_count + 1;
    }

    fn wait(self: *KQueue, timeout_sec: ?i32) !Iterator {
        const event_list = &self.event_list;
        const timeout: ?posix.timespec = if (timeout_sec) |ts| posix.timespec{ .sec = ts, .nsec = 0 } else null;
        const event_count = try posix.kevent(self.q, self.change_buffer[0..self.change_count], event_list, if (timeout) |ts| &ts else null);
        self.change_count = 0;

        return .{
            .index = 0,
            .events = event_list[0..event_count],
        };
    }

    const Iterator = struct {
        index: usize,
        events: []Kevent,

        fn next(self: *Iterator) ?usize {
            const index = self.index;
            const events = self.events;
            if (index == events.len) {
                return null;
            }
            self.index = index + 1;
            return self.events[index].udata;
        }
    };
};

const EPoll = struct {
    q: i32,
    event_list: [64]EpollEvent,

    const linux = std.os.linux;
    const EpollEvent = linux.epoll_event;

    fn init() !EPoll {
        return .{
            .event_list = undefined,
            .q = try posix.epoll_create1(0),
        };
    }

    fn deinit(self: EPoll) void {
        posix.close(self.q);
    }

    fn monitorAccept(self: *EPoll, fd: c_int) !void {
        var event = linux.epoll_event{ .events = linux.EPOLL.IN, .data = .{ .ptr = 0 } };
        return std.posix.epoll_ctl(self.q, linux.EPOLL.CTL_ADD, fd, &event);
    }

    fn monitorSignal(self: *EPoll, fd: c_int) !void {
        var event = linux.epoll_event{ .events = linux.EPOLL.IN, .data = .{ .ptr = 1 } };
        return std.posix.epoll_ctl(self.q, linux.EPOLL.CTL_ADD, fd, &event);
    }

    fn monitorRead(self: *EPoll, hc: anytype, comptime rearm: bool) !void {
        const op = if (rearm) linux.EPOLL.CTL_MOD else linux.EPOLL.CTL_ADD;
        var event = linux.epoll_event{ .events = linux.EPOLL.IN | linux.EPOLL.ONESHOT, .data = .{ .ptr = @intFromPtr(hc) } };
        return posix.epoll_ctl(self.q, op, hc.socket, &event);
    }

    fn wait(self: *EPoll, timeout_sec: ?i32) !Iterator {
        const event_list = &self.event_list;
        var timeout: i32 = -1;
        if (timeout_sec) |sec| {
            if (sec > 2147483) {
                // max supported timeout by epoll_wait.
                timeout = 2147483647;
            } else {
                timeout = sec * 1000;
            }
        }

        const event_count = posix.epoll_wait(self.q, event_list, timeout);
        return .{
            .index = 0,
            .events = event_list[0..event_count],
        };
    }

    const Iterator = struct {
        index: usize,
        events: []EpollEvent,

        fn next(self: *Iterator) ?usize {
            const index = self.index;
            const events = self.events;
            if (index == events.len) {
                return null;
            }
            self.index = index + 1;
            return self.events[index].data.ptr;
        }
    };
};

// We want to extract as much common logic as possible from the Blocking and
// NonBlockign workers. The code from this point on is meant to be used with
// both workers, independently from the blocking/nonblocking nonsense.

// Abstraction ontop of NonBlocking and Blocking. Exists solely for integration
// with httpz (or any other http library I guess.). Serves a similar purpose
// as Server, but doesn't accept/listen.
pub fn Worker(comptime H: type) type {
    return struct {
        worker: W,

        const Self = @This();
        const W = if (blockingMode()) Blocking(H) else NonBlockingBase(H, false);

        pub fn init(allocator: Allocator, state: *WorkerState) !Self {
            return .{
                .worker = try W.init(allocator, state),
            };
        }

        pub fn deinit(self: *Self) void {
            self.worker.deinit();
        }

        pub fn createConn(self: *Self, socket: posix.socket_t, address: net.Address, now: u32) !*HandlerConn(H) {
            return self.worker.conn_manager.create(socket, address, now);
        }

        pub fn cleanupConn(self: *Self, hc: *HandlerConn(H)) void {
            self.worker.cleanupConn(hc);
        }

        pub fn canCompress(self: *const Self) bool {
            return self.worker.conn_manager.compression != null;
        }

        pub fn setupConnection(
            self: *Self,
            hc: *HandlerConn(H),
        ) !void {
            return self.worker.conn_manager.setupCompression(hc);
        }

        pub fn shutdown(self: *Self) void {
            self.worker.shutdown();
        }
    };
}

// These are things that both the Blocking and NonBlocking workers need. Just cleaner
// to have a single place for it. This could used to be directly in Server(H), with
// Server(H) having handshake_pool and buffer_provider fields, but it was extracted
// into its own struct for integration with webservers (i.e. httpz). The goal is
// that a webserver can have websocket support without starting a full Server.
pub const WorkerState = struct {
    config: Config,
    handshake_pool: *Handshake.Pool,
    buffer_provider: buffer.Provider,

    pub fn init(allocator: Allocator, config: Config) !WorkerState {
        const handshake_pool_count = config.handshake.count orelse 32;
        const handshake_max_size = config.handshake.max_size orelse 1024;
        const handshake_max_headers = config.handshake.max_headers orelse 10;
        const handshake_max_res_headers = config.handshake.max_res_headers orelse 2;

        var handshake_pool = try Handshake.Pool.init(allocator, handshake_pool_count, handshake_max_size, handshake_max_headers, handshake_max_res_headers);
        errdefer handshake_pool.deinit();

        const max_message_size = config.max_message_size orelse DEFAULT_MAX_MESSAGE_SIZE;
        const large_buffer_pool = config.buffers.large_pool orelse 8;
        const large_buffer_size = config.buffers.large_size orelse @min((config.buffers.small_size orelse DEFAULT_BUFFER_SIZE) * 2, max_message_size);

        var buffer_provider = try buffer.Provider.init(allocator, .{
            .max = max_message_size,
            .size = large_buffer_size,
            .count = large_buffer_pool,
        });
        errdefer buffer_provider.deinit();

        return .{
            .config = config,
            .handshake_pool = handshake_pool,
            .buffer_provider = buffer_provider,
        };
    }

    pub fn deinit(self: *WorkerState) void {
        self.handshake_pool.deinit();
        self.buffer_provider.deinit();
    }
};

// In the Blocking worker, all the state could be stored on the spawn'd threads
// stack. The only reason we use a HandlerConn(H) in there is to be able to re-use
// code with the NonBlocking worker.
//
// For the NonBlocking worker, HandlerConn(H) is critical as it contains all the
// state for a connection. It lives on the heap, a pointer is registered into
// the event loop, and passed back when data is ready to read.
// * If handler is null, it means we haven't done our handshake yet.
// * If handler is null AND handshake is null, it means we havent' received
//   any data yet (we delay creating the handshake state until we at least have
//   some data ready).
pub fn HandlerConn(comptime H: type) type {
    return struct {
        state: State,
        conn: Conn,
        handler: ?H,
        reader: ?Reader,
        socket: posix.socket_t, // denormalization from conn.stream.handle
        handshake: ?*Handshake.State,
        cleanup: Thread.Mutex = .{},
        compression: ?Compression = null,
        next: ?*HandlerConn(H) = null,
        prev: ?*HandlerConn(H) = null,

        const State = enum {
            handshake,
            active,
        };
    };
}

pub fn ConnManager(comptime H: type, comptime MANAGE_HS: bool) type {
    return struct {
        lock: Thread.Mutex,
        allocator: Allocator,
        active: List(HandlerConn(H)),
        pending: List(HandlerConn(H)),
        pool: std.heap.MemoryPool(HandlerConn(H)),
        compression: ?Compression,
        compression_pool: std.heap.MemoryPool(Conn.Compression),

        const Self = @This();

        pub fn init(allocator: Allocator, compression: ?Compression) !Self {
            var pool = std.heap.MemoryPool(HandlerConn(H)).init(allocator);
            errdefer pool.deinit();

            var compression_pool = std.heap.MemoryPool(Conn.Compression).init(allocator);
            errdefer compression_pool.deinit();

            return .{
                .lock = .{},
                .pool = pool,
                .active = .{},
                .pending = .{},
                .allocator = allocator,
                .compression = compression,
                .compression_pool = compression_pool,
            };
        }

        pub fn deinit(self: *Self) void {
            self.pool.deinit();
            self.compression_pool.deinit();
        }

        pub fn count(self: *Self) usize {
            self.lock.lock();
            defer self.lock.unlock();
            if (MANAGE_HS == false) {
                return self.active.len;
            }
            return self.active.len + self.pending.len;
        }

        pub fn create(self: *Self, socket: posix.socket_t, address: net.Address, now: u32) !*HandlerConn(H) {
            // Blocking mode: the socket is non-blocking from here on.
            var blocking: Conn.BlockingState = if (comptime blockingMode()) .{
                .waiter = socket_wait.Waiter.init(socket, .read) catch |err| {
                    closeSocketHandle(socket);
                    return err;
                },
            } else {};
            // The socket first, then its event (closesocket ends the
            // socket's use of it).
            errdefer if (comptime blockingMode()) blocking.waiter.deinit();
            errdefer closeSocketHandle(socket);

            self.lock.lock();
            defer self.lock.unlock();

            const hc = try self.pool.create();
            hc.* = .{
                .state = if (MANAGE_HS) .handshake else .active,
                .socket = socket,
                .handler = null,
                .handshake = null,
                .reader = null,
                .compression = null,
                .conn = .{
                    ._closed = false,
                    .started = now,
                    .address = address,
                    .stream = .{ .handle = socket },
                    .compression = null,
                    .blocking = blocking,
                },
            };

            if (comptime MANAGE_HS) {
                // Still waiting for a handshake. Only care about this with the full
                // NonBlocking worker
                self.pending.insert(hc);
            } else {
                self.active.insert(hc);
            }
            return hc;
        }

        pub fn activate(self: *Self, hc: *HandlerConn(H)) void {
            std.debug.assert(MANAGE_HS == true);

            // our caller made sute this was the case
            std.debug.assert(hc.state == .handshake);
            self.lock.lock();
            defer self.lock.unlock();
            self.pending.remove(hc);
            self.active.insert(hc);
            hc.state = .active;
        }

        pub fn inactive(self: *Self, hc: *HandlerConn(H)) void {
            std.debug.assert(MANAGE_HS == true);

            // this should only be called when we need more data to complete the handshake
            // which should only happen on an active connection
            std.debug.assert(hc.state == .active);
            hc.state = .handshake;

            self.lock.lock();
            defer self.lock.unlock();
            self.active.remove(hc);
            self.pending.insert(hc);
        }

        /// Closes the connection's handler, if it is still open. A NonBlocking
        /// shutdownCleanup closes it from the event-loop thread: hc.cleanup
        /// makes one of the two do it, and neither while the other is still
        /// in it. Not called under self.lock, which shutdown holds while
        /// taking hc.cleanup.
        pub fn closeHandler(_: *Self, hc: *HandlerConn(H)) void {
            hc.cleanup.lock();
            defer hc.cleanup.unlock();
            if (hc.handler) |*h| {
                if (comptime std.meta.hasFn(H, "close")) {
                    h.close();
                }
                hc.handler = null;
            }
        }

        pub fn cleanup(self: *Self, hc: *HandlerConn(H)) void {
            if (hc.handshake) |h| {
                h.release();
            }

            if (hc.reader) |*r| {
                r.deinit();
            }

            self.closeHandler(hc);

            if (hc.conn.compression) |c| {
                c.writer.deinit();
            }

            self.lock.lock();
            if (hc.state == .active) {
                self.active.remove(hc);
            } else {
                self.pending.remove(hc);
            }

            if (hc.conn.compression) |c| {
                self.compression_pool.destroy(c);
            }

            self.pool.destroy(hc);
            self.lock.unlock();
        }

        fn setupCompression(self: *Self, hc: *HandlerConn(H)) !void {
            const config = self.compression orelse return;

            hc.compression = config;

            if (config.write_threshold == null) {
                // if write_treshold is null, then we never want to compress
                // outgoing messages. We don't need to set the conn.compression
                // field.
                // We'll still [potentially] decompress incoming messages, but
                // that's set on the proto.
                return;
            }

            const compression = try self.compression_pool.create();
            errdefer self.compression_pool.destroy(compression);

            compression.* = .{
                .allocator = self.allocator,
                .write_treshold = config.write_threshold.?,
                .retain_writer = config.retain_write_buffer,
                .writer = std.Io.Writer.Allocating.init(self.allocator),
            };
            hc.conn.compression = compression;
        }

        pub fn shutdown(self: *Self, worker: anytype) void {
            self.lock.lock();
            defer self.lock.unlock();

            shutdownList(self.active.head, worker);
            shutdownList(self.pending.head, worker);
        }

        // This is sloppy and leaves things in an unrecoverable state. To keep
        // things clean, we should call self.cleanup(hc) on each entry in the list
        // but that does a bunch of things we don't need if we know that we're
        // shutting down - like returning data to the pools, and popping items
        // out of the list.
        // Ending a connection is the worker's (shutdownCleanup). NonBlocking
        // only: a Blocking worker's connections end on their own threads,
        // at its stop signal.
        fn shutdownList(head: ?*HandlerConn(H), worker: anytype) void {
            var next_node = head;
            while (next_node) |hc| {
                worker.shutdownCleanup(hc);
                next_node = hc.next;
            }
        }
    };
}

// This is what actually gets exposed to the app
pub const Conn = struct {
    _closed: bool,
    started: u32,
    stream: net.Stream,
    address: net.Address,
    lock: Thread.Mutex = .{},
    /// NonBlocking mode: orders closing the socket against shutting it down
    /// from another thread: on a closed socket that fails with EBADF
    /// (unreachable in posix.shutdown), and on a reused descriptor it would
    /// end someone else's connection. Never held across a send; `lock` may
    /// be (a standalone NonBlocking server's sockets are blocking), so it
    /// can't serve for this.
    socket_lock: Thread.Mutex = .{},
    compression: ?*Conn.Compression = null,
    blocking: BlockingState,

    /// Bytes of already-started frames the socket did not take yet. Sockets
    /// are non-blocking: when one is full, the rest of the frame waits here
    /// (and later frames queue behind it) rather than being abandoned
    /// mid-frame, which would corrupt the stream for good. Drained by later
    /// writes and by flushPending. Protected by `lock`.
    pending: std.ArrayListUnmanaged(u8) = .empty,
    /// Bytes at the front of `pending` already sent.
    pending_head: usize = 0,

    /// A peer this far behind is not reading; it is disconnected rather than
    /// queued for without bound.
    pub const max_pending_bytes: usize = 16 * 1024 * 1024;

    /// Blocking mode's per-connection state. The connection's own thread
    /// alone closes the socket (release); another thread can only ask it to
    /// (requestEnd), so no thread ever uses a closed or reused socket.
    pub const BlockingState = if (blockingMode()) struct {
        waiter: socket_wait.Waiter,
        /// The socket is closed. Guarded by `lock`.
        released: bool = false,
        /// Reset the connection rather than close it gracefully: output for
        /// it was dropped, or it stopped reading. Guarded by `lock`.
        abortive: bool = false,
        /// A standalone server's handshake deadline, in
        /// std.time.milliTimestamp's terms. The connection's thread's.
        handshake_deadline_ms: ?i64 = null,
    } else void;

    const Compression = struct {
        allocator: Allocator,
        retain_writer: bool,
        write_treshold: usize,
        writer: std.Io.Writer.Allocating,
    };

    pub fn isClosed(self: *Conn) bool {
        // don't use lock to protect _closed. `isClosed` is called from
        // the worker thread and we don't want that potentially blocked while
        // a write is going on.
        return @atomicLoad(bool, &self._closed, .acquire);
    }

    pub fn writeBin(self: *Conn, data: []const u8) !void {
        return self.writeFrame(.binary, data);
    }

    pub fn writeText(self: *Conn, data: []const u8) !void {
        return self.writeFrame(.text, data);
    }

    pub fn write(self: *Conn, data: []const u8) !void {
        return self.writeFrame(.text, data);
    }

    pub fn writePing(self: *Conn, data: []u8) !void {
        return self.writeFrame(.ping, data);
    }

    pub fn writePong(self: *Conn, data: []u8) !void {
        return self.writeFrame(.pong, data);
    }

    const CloseOpts = struct {
        code: u16 = 1000,
        reason: []const u8 = "",
    };

    pub fn close(self: *Conn, opts: CloseOpts) !void {
        if (comptime blockingMode()) return self.closeBlocking(opts);
        if (self.isClosed()) {
            return;
        }
        defer self.closeSocket();

        const reason = opts.reason;
        if (reason.len == 0) {
            var buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &buf, opts.code, .big);
            return self.writeFrame(.close, &buf);
        }

        if (reason.len > 123) {
            return error.ReasonTooLong;
        }

        var buf: [4]u8 = undefined;
        buf[0] = @intFromEnum(OpCode.close);
        buf[1] = @intCast(reason.len + 2);
        std.mem.writeInt(u16, buf[2..], opts.code, .big);

        var vec = [2]std.posix.iovec_const{
            .{ .len = buf.len, .base = &buf },
            .{ .len = reason.len, .base = reason.ptr },
        };

        try writeAllIOVec(self, &vec);
    }

    /// Blocking mode: the close frame is the last thing written (no other
    /// thread's frame can follow it), and the connection's own thread then
    /// closes the socket.
    fn closeBlocking(self: *Conn, opts: CloseOpts) !void {
        self.lock.lock();
        defer self.lock.unlock();
        if (self.isClosed()) return;
        defer self.requestEndLocked(false);

        const reason = opts.reason;
        if (reason.len > 123) return error.ReasonTooLong;
        var payload: [125]u8 = undefined;
        std.mem.writeInt(u16, payload[0..2], opts.code, .big);
        @memcpy(payload[2..][0..reason.len], reason);
        var header_buf: [10]u8 = undefined;
        const header = proto.writeFrameHeader(&header_buf, .close, reason.len + 2, false);
        var vec = [2]std.posix.iovec_const{
            .{ .len = header.len, .base = header.ptr },
            .{ .len = reason.len + 2, .base = &payload },
        };
        return self.writeAllIOVecLocked(&vec);
    }

    pub fn writeFrame(self: *Conn, op_code: OpCode, data: []const u8) !void {
        const payload = data;

        // Zig 0.15 compression disabled
        const compressed = false;
        // if (self.compression) |c| {
        //     if (data.len >= c.write_treshold) {
        //         compressed = true;
        //         var compressor = std.compress.flate.Compress.init(&c.writer.writer, &.{}, .{});
        //         try compressor.writer.writeAll(data);
        //         try compressor.writer.flush();
        //         const all = c.writer.written();
        //         payload = all[0 .. all.len - 4];
        //     }
        // }

        // defer if (compressed) {
        //     const c = self.compression.?;
        //     if (c.retain_writer) {
        //         c.writer.clearRetainingCapacity();
        //     } else {
        //         c.writer.deinit();
        //         c.writer = std.Io.Writer.Allocating.init(c.allocator);
        //     }
        // };

        // maximum possible prefix length. op_code + length_type + 8byte length
        var buf: [10]u8 = undefined;
        const header = proto.writeFrameHeader(&buf, op_code, payload.len, compressed);

        if (payload.len == 0) {
            // no body, just write the header
            var vec = [1]std.posix.iovec_const{.{ .len = header.len, .base = header.ptr }};
            return self.writeAllIOVec(&vec);
        }

        var vec = [2]std.posix.iovec_const{
            .{ .len = header.len, .base = header.ptr },
            .{ .len = payload.len, .base = payload.ptr },
        };

        return self.writeAllIOVec(&vec);
    }

    pub fn writeFramed(self: *Conn, data: []const u8) !void {
        var vec = [1]std.posix.iovec_const{.{ .len = data.len, .base = data.ptr }};
        return self.writeAllIOVec(&vec);
    }

    /// Send as much of the queued output as the socket takes now. Never
    /// blocks; call it regularly while hasPendingOutput() (e.g. on a timer).
    pub fn flushPending(self: *Conn) !void {
        self.lock.lock();
        defer self.lock.unlock();
        if (self.isClosed()) return;
        try self.flushPendingLocked();
    }

    /// Whether output is queued behind a full socket.
    pub fn hasPendingOutput(self: *Conn) bool {
        self.lock.lock();
        defer self.lock.unlock();
        return self.pendingLen() > 0;
    }

    fn pendingLen(self: *const Conn) usize {
        return self.pending.items.len - self.pending_head;
    }

    fn flushPendingLocked(self: *Conn) !void {
        if (comptime blockingMode()) std.debug.assert(!self.blocking.released);
        while (self.pendingLen() > 0) {
            const n = sendSome(self.stream.handle, self.pending.items[self.pending_head..]) catch |err| switch (err) {
                error.WouldBlock => return,
                else => {
                    if (comptime blockingMode()) self.requestEndLocked(true);
                    return err;
                },
            };
            self.pending_head += n;
        }
        self.pending.clearAndFree(std.heap.smp_allocator);
        self.pending_head = 0;
    }

    /// One non-blocking send. Windows uses send(): posix.write goes through
    /// WriteFile, which fails on sockets in Zig 0.15. Elsewhere see sendVec.
    fn sendSome(socket: net.Stream.Handle, data: []const u8) SendError!usize {
        if (builtin.os.tag == .windows) {
            const ws2 = std.os.windows.ws2_32;
            const rc = ws2.send(socket, data.ptr, @intCast(data.len), 0);
            if (rc == ws2.SOCKET_ERROR) {
                return switch (ws2.WSAGetLastError()) {
                    // Out of buffer space for now: as good as full.
                    .WSAEWOULDBLOCK, .WSAENOBUFS => error.WouldBlock,
                    else => error.BrokenPipe,
                };
            }
            return @intCast(rc);
        }
        return sendVec(socket, &.{.{ .base = data.ptr, .len = data.len }});
    }

    /// One non-blocking send of `vec` (POSIX only) that never raises SIGPIPE.
    /// A send to a peer that has gone away raises SIGPIPE unless the call
    /// passes MSG_NOSIGNAL, and SIGPIPE's default action ends the process:
    /// when the application is a plugin, its host. Whether the host catches
    /// SIGPIPE isn't the library's to know, and a handler installed for it
    /// can be replaced by anything else in the process. So every send passes
    /// MSG_NOSIGNAL, through sendmsg (writev() takes no flags), and a dead
    /// peer is just error.BrokenPipe. Darwin sockets also get SO_NOSIGPIPE
    /// when accepted (`suppressSigpipe`).
    ///
    /// Errors: EAGAIN is WouldBlock, EPIPE BrokenPipe, ECONNRESET
    /// ConnectionResetByPeer, ENOTCONN SocketNotConnected, ENOBUFS and ENOMEM
    /// SystemResources, EBADF NotOpenForWriting (a send can race the
    /// connection's close; see writeAllIOVecLocked) and ENOTSOCK
    /// FileDescriptorNotASocket. Every other errno is error.Unexpected:
    /// nothing is unreachable, unlike posix.sendmsg, which treats EBADF,
    /// ENOTSOCK, EINVAL, EFAULT and EOPNOTSUPP as unreachable.
    fn sendVec(socket: net.Stream.Handle, vec: []const posix.iovec_const) SendError!usize {
        comptime std.debug.assert(builtin.os.tag != .windows);
        const msg: posix.msghdr_const = .{
            .name = null,
            .namelen = 0,
            .iov = vec.ptr,
            .iovlen = @intCast(@min(vec.len, posix.IOV_MAX)),
            .control = null,
            .controllen = 0,
            .flags = 0,
        };
        while (true) {
            const rc = posix.system.sendmsg(socket, &msg, posix.MSG.NOSIGNAL);
            switch (posix.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .INTR => continue,
                .AGAIN => return error.WouldBlock,
                .PIPE => return error.BrokenPipe,
                .CONNRESET => return error.ConnectionResetByPeer,
                .NOTCONN => return error.SocketNotConnected,
                .NOBUFS, .NOMEM => return error.SystemResources,
                .BADF => return error.NotOpenForWriting,
                .NOTSOCK => return error.FileDescriptorNotASocket,
                else => |err| return posix.unexpectedErrno(err),
            }
        }
    }

    /// Queue what is left of `vec` behind a full socket, or give up on a peer
    /// that has stopped reading.
    fn queueLocked(self: *Conn, vec: []const std.posix.iovec_const) !void {
        var total: usize = self.pendingLen();
        for (vec) |v| total += v.len;
        if (total > max_pending_bytes) {
            // Not reading: end the connection (the worker cleans it up when
            // its read sees the shutdown) instead of tearing a frame.
            log.debug("({f}) peer not reading, {d} bytes behind; disconnecting", .{ self.address, total });
            if (comptime blockingMode()) {
                self.requestEndLocked(true);
            } else {
                self.pending.clearAndFree(std.heap.smp_allocator);
                self.pending_head = 0;
                self.shutdownSocket(.both);
            }
            return error.BrokenPipe;
        }
        // Drop what was already sent once it outweighs what is left.
        if (self.pending_head > 0 and self.pending_head >= self.pendingLen()) {
            const rest = self.pendingLen();
            std.mem.copyForwards(u8, self.pending.items[0..rest], self.pending.items[self.pending_head..]);
            self.pending.shrinkRetainingCapacity(rest);
            self.pending_head = 0;
        }
        try self.pending.ensureUnusedCapacity(std.heap.smp_allocator, total - self.pendingLen());
        for (vec) |v| self.pending.appendSliceAssumeCapacity(v.base[0..v.len]);
    }

    /// Write whole frames or queue the rest: a frame is never abandoned
    /// part-way, since the peer would then read every later byte as part of it.
    fn writeAllIOVec(self: *Conn, vec: []std.posix.iovec_const) !void {
        self.lock.lock();
        defer self.lock.unlock();
        return self.writeAllIOVecLocked(vec);
    }

    fn writeAllIOVecLocked(self: *Conn, vec: []std.posix.iovec_const) !void {
        // Its descriptor may already belong to another socket. In blocking
        // mode the socket is closed under `lock`, so this is exact; in
        // NonBlocking mode a send that started before the close can still
        // reach it.
        if (self.isClosed()) return error.Closed;
        self.sendAllLocked(vec) catch |err| {
            // A frame may be part-sent: nothing more can follow it.
            if (comptime blockingMode()) self.requestEndLocked(true);
            return err;
        };
    }

    fn sendAllLocked(self: *Conn, vec: []std.posix.iovec_const) !void {
        if (comptime blockingMode()) std.debug.assert(!self.blocking.released);

        if (self.pendingLen() > 0) {
            // Earlier output is still queued: this frame goes behind it.
            try self.queueLocked(vec);
            return self.flushPendingLocked();
        }

        var i: usize = 0;
        while (i < vec.len) {
            var n: usize = if (builtin.os.tag == .windows)
                sendSome(self.stream.handle, vec[i].base[0..vec[i].len]) catch |err| switch (err) {
                    error.WouldBlock => return self.queueLocked(vec[i..]),
                    else => return err,
                }
            else
                sendVec(self.stream.handle, vec[i..]) catch |err| switch (err) {
                    error.WouldBlock => return self.queueLocked(vec[i..]),
                    else => return err,
                };
            while (i < vec.len and n >= vec[i].len) {
                n -= vec[i].len;
                i += 1;
            }
            if (i < vec.len) {
                vec[i].base += n;
                vec[i].len -= n;
            }
        }
    }

    pub fn writeBuffer(self: *Conn, allocator: Allocator, op_code: OpCode) Writer {
        return .{
            .conn = self,
            .buf = .empty,
            .op_code = op_code,
            .allocator = allocator,
            .interface = .{
                .vtable = &.{ .drain = Writer.drain },
                .buffer = &.{},
            },
        };
    }

    fn closeSocket(self: *Conn) void {
        const closed_here = blk: {
            self.socket_lock.lock();
            defer self.socket_lock.unlock();
            break :blk self.closeLocked();
        };
        if (closed_here) self.dropPending();
    }

    /// Under socket_lock. True if this call closed the socket.
    fn closeLocked(self: *Conn) bool {
        if (@atomicRmw(bool, &self._closed, .Xchg, true, .acq_rel)) return false;
        closeSocketHandle(self.stream.handle);
        return true;
    }

    /// Once the socket is closed: output still queued for it can't be sent.
    fn dropPending(self: *Conn) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.pending.clearAndFree(std.heap.smp_allocator);
        self.pending_head = 0;
    }

    /// Blocking mode, on the connection's own thread: reads what is there,
    /// waiting (on the socket and on `stop`) while there is nothing.
    /// error.Stopped once `stop` is set, error.Closed once the connection
    /// was asked to end or the peer closed, error.Timeout at `deadline_ms`
    /// (std.time.milliTimestamp's terms).
    fn recvSome(self: *Conn, buf: []u8, stop: *const socket_wait.Stop, deadline_ms: ?i64) !usize {
        while (true) {
            if (stop.isSet()) return error.Stopped;
            if (self.isClosed()) return error.Closed;
            const n = socket_wait.recv(self.stream.handle, buf) catch |err| switch (err) {
                error.WouldBlock => {
                    const timeout_ms: ?u32 = if (deadline_ms) |deadline| blk: {
                        const left = deadline - std.time.milliTimestamp();
                        if (left <= 0) return error.Timeout;
                        break :blk @intCast(@min(left, std.math.maxInt(u31)));
                    } else null;
                    self.blocking.waiter.wait(self.stream.handle, stop, timeout_ms) catch |wait_err| switch (wait_err) {
                        // recv sees the deadline next time round
                        error.Timeout => {},
                        else => return wait_err,
                    };
                    continue;
                },
                else => return err,
            };
            if (n == 0) return error.Closed;
            return n;
        }
    }

    /// Blocking mode, under `lock`: ends the connection from any thread.
    /// Later writes fail; the connection's thread wakes (or sees it after
    /// the message it is handling), closes the handler, then the socket.
    fn requestEndLocked(self: *Conn, abortive: bool) void {
        if (self.blocking.released) return;
        // Dropping part of a frame leaves the stream unusable: reset it.
        if (abortive or self.pendingLen() > 0) self.blocking.abortive = true;
        self.pending.clearAndFree(std.heap.smp_allocator);
        self.pending_head = 0;
        @atomicStore(bool, &self._closed, true, .release);
        self.blocking.waiter.wake(self.stream.handle);
    }

    /// Blocking mode, on the connection's own thread once its handler is
    /// closed: closes the socket, under `lock`, so no writer can use it after
    /// (in blocking mode no send waits, so `lock` is never held long). Reset
    /// rather than closed gracefully when output was dropped or is still
    /// queued: the stream is torn, or the peer is behind and may never read
    /// what the system would go on trying to send it. Otherwise graceful,
    /// even when the server is stopping: a reset would make the peer
    /// discard what it has received and not yet read (Windows does).
    pub fn release(self: *Conn) void {
        self.lock.lock();
        defer self.lock.unlock();
        if (self.blocking.released) return;
        self.blocking.released = true;
        @atomicStore(bool, &self._closed, true, .release);
        const abortive = self.blocking.abortive or self.pendingLen() > 0;
        self.pending.clearAndFree(std.heap.smp_allocator);
        self.pending_head = 0;
        socket_wait.closeSocket(self.stream.handle, abortive);
        self.blocking.waiter.deinit();
    }

    /// Shuts the socket down unless it has been closed.
    fn shutdownSocket(self: *Conn, how: posix.ShutdownHow) void {
        self.socket_lock.lock();
        defer self.socket_lock.unlock();
        if (self.isClosed()) return;
        posix.shutdown(self.stream.handle, how) catch {};
    }

    pub const Writer = struct {
        conn: *Conn,
        op_code: OpCode,
        allocator: Allocator,
        buf: std.ArrayList(u8),
        interface: std.Io.Writer,

        pub const Error = Allocator.Error;

        pub fn deinit(self: *Writer) void {
            self.buf.deinit(self.allocator);
        }

        pub fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) error{WriteFailed}!usize {
            _ = splat;
            const self: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
            self.buf.appendSlice(self.allocator, data[0]) catch return error.WriteFailed;
            return data[0].len;
        }

        pub fn send(self: *Writer) !void {
            return self.conn.writeFrame(self.op_code, self.buf.items) catch error.WriteFailed;
        }
    };
};

fn handleHandshake(comptime H: type, worker: anytype, hc: *HandlerConn(H), ctx: anytype) struct { bool, bool } {
    return _handleHandshake(H, worker, hc, ctx) catch |err| {
        log.warn("({f}) uncaugh error processing handshake: {}", .{ hc.conn.address, err });
        return .{ false, false };
    };
}

fn _handleHandshake(comptime H: type, worker: anytype, hc: *HandlerConn(H), ctx: anytype) !struct { bool, bool } {
    std.debug.assert(hc.handler == null);

    var state = hc.handshake orelse blk: {
        const s = try worker.handshake_pool.acquire();
        hc.handshake = s;
        break :blk s;
    };

    var buf = state.buf;
    var conn = &hc.conn;
    const len = state.len;

    if (len == buf.len) {
        log.warn("({f}) handshake request exceeded maximum configured size ({d})", .{ conn.address, buf.len });
        return .{ false, false };
    }

    const read = if (comptime blockingMode())
        conn.recvSome(buf[len..], &worker.stop, conn.blocking.handshake_deadline_ms)
    else
        posix.read(hc.socket, buf[len..]);
    const n = read catch |err| {
        // anyerror: each mode's read fails with its own set.
        switch (@as(anyerror, err)) {
            error.BrokenPipe, error.ConnectionResetByPeer, error.Closed, error.Stopped => log.debug("({f}) handshake connection closed: {}", .{ conn.address, err }),
            error.Timeout, error.WouldBlock => log.debug("({f}) handshake timeout", .{conn.address}),
            else => log.warn("({f}) handshake error reading from socket: {}", .{ conn.address, err }),
        }
        return .{ false, false };
    };

    if (n == 0) {
        log.debug("({f}) handshake connection closed", .{conn.address});
        return .{ false, false };
    }

    state.len = len + n;
    var handshake = Handshake.parse(state) catch |err| {
        log.debug("({f}) error parsing handshake: {}", .{ conn.address, err });
        respondToHandshakeError(conn, err);
        return .{ false, false };
    } orelse {
        // we need more data
        return .{ false, true };
    };

    const compression = handshake.compression != null and worker.compression != null;
    defer state.release();
    hc.handshake = null;

    // After this, the app has access to &hc.conn, so any access to the
    // conn has to be synchronized (which the conn does internally).

    const handler = H.init(&handshake, conn, ctx) catch |err| {
        if (comptime std.meta.hasFn(H, "handshakeErrorResponse")) {
            preHandOffWrite(conn, H.handshakeErrorResponse(err));
        } else {
            respondToHandshakeError(conn, err);
        }
        log.debug("({f}) " ++ @typeName(H) ++ ".init rejected request {}", .{ conn.address, err });
        return .{ false, false };
    };

    hc.handler = handler;

    var reply_buf: [2048]u8 = undefined;
    const handshake_reply = try Handshake.createReply(handshake.key, handshake.res_headers, compression, &reply_buf);
    try conn.writeFramed(handshake_reply);

    if (comptime std.meta.hasFn(H, "afterInit")) {
        const params = @typeInfo(@TypeOf(H.afterInit)).@"fn".params;
        const res = if (params.len == 1) hc.handler.?.afterInit() else hc.handler.?.afterInit(ctx);
        res catch |err| {
            log.debug("({f}) " ++ @typeName(H) ++ ".afterInit error: {}", .{ conn.address, err });
            return .{ false, false };
        };
    }

    log.debug("({f}) connection successfully upgraded", .{conn.address});
    return .{ compression, true };
}

/// Blocking mode's stop signal; nothing in NonBlocking mode.
const StopRef = if (blockingMode()) *const socket_wait.Stop else void;

fn handleClientData(comptime H: type, hc: *HandlerConn(H), allocator: Allocator, fba: *FixedBufferAllocator, stop: StopRef) bool {
    std.debug.assert(hc.handshake == null);
    return _handleClientData(H, hc, allocator, fba, stop) catch |err| {
        log.warn("({f}) uncaugh error handling incoming data: {}", .{ hc.conn.address, err });
        return false;
    };
}

fn _handleClientData(comptime H: type, hc: *HandlerConn(H), allocator: Allocator, fba: *FixedBufferAllocator, stop: StopRef) !bool {
    var conn = &hc.conn;
    var reader = &hc.reader.?;
    const filled = if (comptime blockingMode())
        reader.fill(BlockingSource{ .conn = conn, .stop = stop })
    else
        reader.fill(conn.stream);
    filled catch |err| {
        // anyerror: each mode's read fails with its own set.
        switch (@as(anyerror, err)) {
            error.Closed, error.Stopped, error.ConnectionResetByPeer => log.debug("({f}) connection closed: {}", .{ conn.address, err }),
            else => log.warn("({f}) error reading from connection: {}", .{ conn.address, err }),
        }
        return false;
    };

    const handler = &hc.handler.?;
    while (true) {
        const has_more, const message = reader.read() catch |err| {
            switch (err) {
                error.LargeControl => conn.writeFramed(CLOSE_PROTOCOL_ERROR) catch {},
                error.ReservedFlags => conn.writeFramed(CLOSE_PROTOCOL_ERROR) catch {},
                error.CompressionDisabled => conn.writeFramed(CLOSE_PROTOCOL_ERROR) catch {},
                error.CompressionError => conn.writeFramed(CLOSE_PROTOCOL_ERROR) catch {},
                else => {},
            }
            log.debug("({f}) invalid websocket packet: {}", .{ conn.address, err });
            return false;
        } orelse {
            // everything is fine, we just need more data
            return true;
        };

        const message_type = message.type;
        defer reader.done(message_type);

        log.debug("({f}) received {s} message", .{ hc.conn.address, @tagName(message_type) });
        switch (message_type) {
            .text, .binary => {
                const params = @typeInfo(@TypeOf(H.clientMessage)).@"fn".params;
                const needs_allocator = comptime needsAllocator(H);

                var arena: std.heap.ArenaAllocator = undefined;
                var fallback_allocator: FallbackAllocator = undefined;
                var aa: Allocator = undefined;

                if (comptime needs_allocator) {
                    arena = std.heap.ArenaAllocator.init(allocator);
                    if (comptime blockingMode()) {
                        aa = arena.allocator();
                    } else {
                        fallback_allocator = FallbackAllocator{
                            .fba = fba,
                            .fallback = arena.allocator(),
                            .fixed = fba.allocator(),
                        };
                        aa = fallback_allocator.allocator();
                    }
                }

                defer if (comptime needs_allocator) {
                    arena.deinit();
                };

                switch (comptime params.len) {
                    2 => handler.clientMessage(message.data) catch return false,
                    3 => if (needs_allocator) {
                        handler.clientMessage(aa, message.data) catch return false;
                    } else {
                        handler.clientMessage(message.data, if (message_type == .text) .text else .binary) catch return false;
                    },
                    4 => handler.clientMessage(aa, message.data, if (message_type == .text) .text else .binary) catch return false,
                    else => @compileError(@typeName(H) ++ ".clientMessage has invalid parameter count"),
                }
            },
            .pong => if (comptime std.meta.hasFn(H, "clientPong")) {
                try handler.clientPong(message.data);
            },
            .ping => {
                const data = message.data;
                if (comptime std.meta.hasFn(H, "clientPing")) {
                    try handler.clientPing(data);
                } else if (data.len == 0) {
                    try hc.conn.writeFramed(EMPTY_PONG);
                } else {
                    try hc.conn.writeFrame(.pong, data);
                }
            },
            .close => {
                const data = message.data;
                if (comptime std.meta.hasFn(H, "clientClose")) {
                    try handler.clientClose(data);
                    return false;
                }

                const l = data.len;
                if (l == 0) {
                    try conn.close(.{});
                    return false;
                }

                if (l == 1) {
                    // close with a payload always has to have at least a 2-byte payload,
                    // since a 2-byte code is required
                    try conn.writeFramed(CLOSE_PROTOCOL_ERROR);
                    return false;
                }

                const code = @as(u16, @intCast(data[1])) | (@as(u16, @intCast(data[0])) << 8);
                if (code < 1000 or code == 1004 or code == 1005 or code == 1006 or (code > 1013 and code < 3000)) {
                    try conn.writeFramed(CLOSE_PROTOCOL_ERROR);
                    return false;
                }

                if (l == 2) {
                    try conn.writeFramed(CLOSE_NORMAL);
                    return false;
                }

                const payload = data[2..];
                if (!std.unicode.utf8ValidateSlice(payload)) {
                    // if we have a payload, it must be UTF8 (why?!)
                    try conn.writeFramed(CLOSE_PROTOCOL_ERROR);
                } else {
                    try conn.close(.{});
                }
                return false;
            },
        }

        if (conn.isClosed()) {
            return false;
        }

        if (has_more == false) {
            // we don't have more data ready to be processed in our buffer
            // back to our caller for more data
            return true;
        }
    }
}

/// Blocking mode: what the connection's thread reads through (Reader.fill
/// calls read).
const BlockingSource = struct {
    conn: *Conn,
    stop: *const socket_wait.Stop,

    pub fn read(self: BlockingSource, buf: []u8) !usize {
        return self.conn.recvSome(buf, self.stop, null);
    }
};

fn needsAllocator(comptime H: type) bool {
    const params = @typeInfo(@TypeOf(H.clientMessage)).@"fn".params;
    return comptime params[1].type == Allocator;
}

fn respondToHandshakeError(conn: *Conn, err: anyerror) void {
    const response = switch (err) {
        error.Close => return,
        error.RequestTooLarge => buildError(400, "too large"),
        error.Timeout, error.WouldBlock => buildError(400, "timeout"),
        error.InvalidProtocol => buildError(400, "invalid protocol"),
        error.InvalidRequestLine => buildError(400, "invalid requestline"),
        error.InvalidHeader => buildError(400, "invalid header"),
        error.InvalidUpgrade => buildError(400, "invalid upgrade"),
        error.InvalidVersion => buildError(400, "invalid version"),
        error.InvalidConnection => buildError(400, "invalid connection"),
        error.MissingHeaders => buildError(400, "missingheaders"),
        error.Empty => buildError(400, "invalid request"),
        else => buildError(400, "unknown"),
    };
    preHandOffWrite(conn, response);
}

fn buildError(comptime status: u16, comptime err: []const u8) []const u8 {
    return std.fmt.comptimePrint("HTTP/1.1 {d} \r\nConnection: Close\r\nError: {s}\r\nContent-Length: 0\r\n\r\n", .{ status, err });
}

fn preHandOffWrite(conn: *Conn, response: []const u8) void {
    // "preHandOff" means we haven't given the application handler a reference
    // to *Conn yet, so no other thread writes to it. The sends return on an
    // error rather than treat a closed socket as unreachable. Best effort: a
    // close follows.
    conn.lock.lock();
    defer conn.lock.unlock();

    if (conn.isClosed()) {
        return;
    }

    const socket = conn.stream.handle;
    if (comptime !blockingMode()) {
        // A standalone NonBlocking server's sockets are blocking: bound the
        // wait on a peer that doesn't read. In blocking mode the socket is
        // non-blocking, and a full one just ends the write.
        const timeout = socketTimeout(5);
        setConnectionOption(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout) catch return;
    }

    var pos: usize = 0;
    while (pos < response.len) {
        const remaining = response[pos..];
        const n = Conn.sendSome(socket, remaining) catch return;
        if (n == 0) {
            // closed
            return;
        }
        pos += n;
    }
}

fn timestamp() u32 {
    if (comptime @hasDecl(posix, "CLOCK") == false or posix.CLOCK == void) {
        return @intCast(std.time.timestamp());
    }
    const ts = posix.clock_gettime(posix.CLOCK.REALTIME) catch unreachable;
    return @intCast(ts.sec);
}

// intrusive doubly-linked list with count, not thread safe
fn List(comptime T: type) type {
    return struct {
        len: usize = 0,
        head: ?*T = null,
        tail: ?*T = null,

        const Self = @This();

        pub fn insert(self: *Self, node: *T) void {
            if (self.tail) |tail| {
                tail.next = node;
                node.prev = tail;
                self.tail = node;
            } else {
                self.head = node;
                self.tail = node;
            }
            self.len += 1;
            node.next = null;
        }

        pub fn remove(self: *Self, node: *T) void {
            if (node.prev) |prev| {
                prev.next = node.next;
            } else {
                self.head = node.next;
            }

            if (node.next) |next| {
                next.prev = node.prev;
            } else {
                self.tail = node.prev;
            }
            node.prev = null;
            node.next = null;
            self.len -= 1;
        }
    };
}

const t = @import("../t.zig");

var test_thread: Thread = undefined;
var test_server: Server(TestHandler) = undefined;
var global_test_allocator = std.heap.GeneralPurposeAllocator(.{}){};

test "tests:beforeAll" {
    test_server = try Server(TestHandler).init(global_test_allocator.allocator(), .{
        .port = 9292,
        .address = "127.0.0.1",
    });
    test_thread = try test_server.listenInNewThread({});
}

test "tests:afterAll" {
    test_server.stop();
    test_thread.join();
    test_server.deinit();
    try t.expectEqual(false, global_test_allocator.detectLeaks());
}

test "Server: invalid handshake" {
    const stream = try testStream(false);
    defer stream.close();

    try stream.writeAll("GET / HTTP/1.1\r\n\r\n");
    var buf: [1024]u8 = undefined;
    var pos: usize = 0;
    while (pos < buf.len) {
        const n = try testRecv(stream, buf[0..]);
        if (n == 0) {
            break;
        }
        pos += n;
    } else {
        unreachable;
    }

    try t.expectString("HTTP/1.1 400 \r\nConnection: Close\r\nError: missingheaders\r\nContent-Length: 0\r\n\r\n", buf[0..pos]);
}

test "Server: read and write" {
    const stream = try testStream(true);
    defer stream.close();

    try stream.writeAll(&proto.frame(.text, "over"));
    var buf: [12]u8 = undefined;
    _ = try testRecvAtLeast(stream, &buf, 6);
    try t.expectSlice(u8, &.{ 129, 4, '9', '0', '0', '0' }, buf[0..6]);
}

test "Server: clientMessage allocator" {
    const stream = try testStream(true);
    defer stream.close();

    try stream.writeAll(&proto.frame(.text, "dyn"));
    var buf: [12]u8 = undefined;
    _ = try testRecvAtLeast(stream, &buf, 12);
    try t.expectSlice(u8, &.{ 129, 10, 'o', 'v', 'e', 'r', ' ', '9', '0', '0', '0', '!' }, buf[0..12]);
}

test "Server: clientMessage writer" {
    const stream = try testStream(true);
    defer stream.close();

    try stream.writeAll(&proto.frame(.text, "writer"));
    var buf: [9]u8 = undefined;
    _ = try testRecvAtLeast(stream, &buf, 9);
    try t.expectSlice(u8, &.{ 129, 7, '9', '0', '0', '0', '!', '!', '!' }, buf[0..9]);
}

// Same as above, but client doesn't shutdown the connection
// When afterAll is runs and things are shutdown, this should still be properly cleaned up
test "Server: dirty clientMessage allocator" {
    const stream = try testStream(true);

    try stream.writeAll(&proto.frame(.text, "dyn"));
    var buf: [12]u8 = undefined;
    _ = try testRecvAtLeast(stream, &buf, 12);
    try t.expectSlice(u8, &.{ 129, 10, 'o', 'v', 'e', 'r', ' ', '9', '0', '0', '0', '!' }, buf[0..12]);
}

/// A Conn on `stream` as a worker sets one up (non-blocking), with a 16 KB
/// send buffer so that it fills quickly.
fn testConn(stream: net.Stream) !Conn {
    const conn = Conn{
        ._closed = false,
        .started = 0,
        .stream = stream,
        .address = try net.Address.parseIp("127.0.0.1", 0),
        .blocking = if (comptime blockingMode()) .{ .waiter = try socket_wait.Waiter.init(stream.handle, .read) } else {},
    };
    if (comptime !blockingMode()) {
        // O_NONBLOCK, not SOCK.NONBLOCK: the latter is a socket() flag, and
        // only on Linux do the two share a value.
        const nonblock: usize = @as(u32, @bitCast(posix.O{ .NONBLOCK = true }));
        const flags = try posix.fcntl(stream.handle, posix.F.GETFL, 0);
        _ = try posix.fcntl(stream.handle, posix.F.SETFL, flags | nonblock);
    }
    try setSendBuffer(stream.handle, 16 * 1024);
    return conn;
}

fn setSendBuffer(socket: posix.socket_t, size: c_int) !void {
    try posix.setsockopt(socket, SOL_SOCKET, SO_SNDBUF, std.mem.asBytes(&size));
}

test "Conn: frames written to a full socket arrive whole and in order" {
    var pair = t.SocketPair.init(.{});
    defer pair.deinit();
    defer pair.server.close();
    var conn = try testConn(pair.server);
    defer conn.pending.deinit(std.heap.smp_allocator);
    defer if (comptime blockingMode()) conn.blocking.waiter.deinit();

    // Nobody reads while four 1 MB frames are written: none may fail and
    // none may be cut short.
    const payload = try t.allocator.alloc(u8, 1024 * 1024);
    defer t.allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i *% 7);
    for (0..4) |i| {
        payload[0] = @intCast(i);
        try conn.writeBin(payload);
    }
    try t.expectEqual(true, conn.hasPendingOutput());

    // The peer starts reading; the writer drains the queue as it goes.
    const expected_len = 4 * (10 + payload.len);
    const received = try t.allocator.alloc(u8, expected_len);
    defer t.allocator.free(received);
    const PeerReader = struct {
        fn run(stream: net.Stream, out: []u8) void {
            _ = testRecvAtLeast(stream, out, out.len) catch unreachable;
        }
    };
    const reader = try std.Thread.spawn(.{}, PeerReader.run, .{ pair.client, received });
    while (conn.hasPendingOutput()) {
        try conn.flushPending();
        std.Thread.sleep(std.time.ns_per_ms);
    }
    reader.join();

    var at: usize = 0;
    for (0..4) |i| {
        // 0x82 = final binary frame, 127 = 8-byte length
        try t.expectEqual(0x82, received[at]);
        try t.expectEqual(127, received[at + 1]);
        try t.expectEqual(payload.len, std.mem.readInt(u64, received[at + 2 ..][0..8], .big));
        try t.expectEqual(@as(u8, @intCast(i)), received[at + 10]);
        try t.expectSlice(u8, payload[1..], received[at + 11 .. at + 10 + payload.len]);
        at += 10 + payload.len;
    }
}

test "Conn: a peer that stops reading is disconnected, not queued for without bound" {
    var pair = t.SocketPair.init(.{});
    defer pair.deinit();
    defer pair.server.close();
    var conn = try testConn(pair.server);
    defer conn.pending.deinit(std.heap.smp_allocator);
    defer if (comptime blockingMode()) conn.blocking.waiter.deinit();

    const payload = try t.allocator.alloc(u8, 1024 * 1024);
    defer t.allocator.free(payload);
    @memset(payload, 'x');
    var failed = false;
    for (0..(Conn.max_pending_bytes / payload.len) + 4) |_| {
        conn.writeBin(payload) catch {
            failed = true;
            break;
        };
    }
    try t.expectEqual(true, failed);
    try t.expectEqual(false, conn.hasPendingOutput());
}

test "Conn: close" {
    {
        // plain close
        const stream = try testStream(true);
        defer stream.close();
        try stream.writeAll(&proto.frame(.text, "close1"));
        var buf: [4]u8 = undefined;
        _ = try testRecvAtLeast(stream, &buf, 4);
        try t.expectSlice(u8, &.{ 136, 2, 3, 232 }, buf[0..4]);
    }

    {
        // close with code
        const stream = try testStream(true);
        defer stream.close();
        try stream.writeAll(&proto.frame(.text, "close2"));
        var buf: [4]u8 = undefined;
        _ = try testRecvAtLeast(stream, &buf, 4);
        try t.expectSlice(u8, &.{ 136, 2, 0, 0x7b }, buf[0..4]);
    }

    {
        // close with reason
        const stream = try testStream(true);
        defer stream.close();
        try stream.writeAll(&proto.frame(.text, "close3"));
        var buf: [7]u8 = undefined;
        _ = try testRecvAtLeast(stream, &buf, 7);
        try t.expectSlice(u8, &.{ 136, 5, 0, 0xea, 'b', 'y', 'e' }, buf[0..7]);
    }
}

// The SIGPIPE tests fork, and in the child put SIGPIPE back to its default
// action (terminate), as in a host process that doesn't catch it: the test
// runner is an executable, whose start code catches SIGPIPE.
const SigpipeOutcome = union(enum) { exited: u8, signaled: u32 };

fn runWithDefaultSigpipe(comptime body: fn () anyerror!void) !SigpipeOutcome {
    const pid = try posix.fork();
    if (pid == 0) {
        const default: posix.Sigaction = .{
            .handler = .{ .handler = posix.SIG.DFL },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        posix.sigaction(posix.SIG.PIPE, &default, null);
        body() catch posix.exit(1);
        posix.exit(0);
    }
    const status = posix.waitpid(pid, 0).status;
    if (posix.W.IFSIGNALED(status)) return .{ .signaled = posix.W.TERMSIG(status) };
    return .{ .exited = posix.W.EXITSTATUS(status) };
}

/// Sends to a peer that has closed its socket until one fails. The first
/// can still succeed: the peer's reset is the answer to it.
fn sendUntilRefused(comptime send: fn (socket: posix.socket_t) anyerror!void) !void {
    var pair = t.SocketPair.init(.{});
    pair.client.close();
    for (0..200) |_| {
        send(pair.server.handle) catch return;
        std.Thread.sleep(std.time.ns_per_ms);
    }
    return error.SendsKeptSucceeding;
}

test "a plain write to a closed peer is killed by SIGPIPE under the default action" {
    // What the tests below guard against, so they can't pass by never
    // reaching it.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const outcome = try runWithDefaultSigpipe(struct {
        fn body() !void {
            try sendUntilRefused(struct {
                fn send(socket: posix.socket_t) !void {
                    _ = try posix.write(socket, "after the peer left");
                }
            }.send);
        }
    }.body);
    try t.expectEqual(SigpipeOutcome{ .signaled = posix.SIG.PIPE }, outcome);
}

test "Conn: frames written to a closed peer fail instead of raising SIGPIPE" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const outcome = try runWithDefaultSigpipe(struct {
        fn body() !void {
            var pair = t.SocketPair.init(.{});
            var conn = try testConn(pair.server);
            pair.client.close();
            for (0..200) |_| {
                conn.writeText("after the peer left") catch return;
                std.Thread.sleep(std.time.ns_per_ms);
            }
            return error.SendsKeptSucceeding;
        }
    }.body);
    try t.expectEqual(SigpipeOutcome{ .exited = 0 }, outcome);
}

test "Conn: a send to a closed peer fails instead of raising SIGPIPE" {
    // sendSome: queued output and handshake responses.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const outcome = try runWithDefaultSigpipe(struct {
        fn body() !void {
            try sendUntilRefused(struct {
                fn send(socket: posix.socket_t) !void {
                    _ = try Conn.sendSome(socket, "after the peer left");
                }
            }.send);
        }
    }.body);
    try t.expectEqual(SigpipeOutcome{ .exited = 0 }, outcome);
}

test "suppressSigpipe: on Darwin even a plain write to a closed peer fails instead of raising SIGPIPE" {
    if (comptime !builtin.os.tag.isDarwin()) return error.SkipZigTest;
    const outcome = try runWithDefaultSigpipe(struct {
        fn body() !void {
            var pair = t.SocketPair.init(.{});
            suppressSigpipe(pair.server.handle);
            pair.client.close();
            for (0..200) |_| {
                _ = posix.write(pair.server.handle, "after the peer left") catch return;
                std.Thread.sleep(std.time.ns_per_ms);
            }
            return error.SendsKeptSucceeding;
        }
    }.body);
    try t.expectEqual(SigpipeOutcome{ .exited = 0 }, outcome);
}

/// The server's end of the connection `client` made to it: the descriptor
/// in this process whose peer address is the client's own address.
fn serverSocketOf(client: posix.socket_t) !posix.socket_t {
    var local: posix.sockaddr.storage = undefined;
    var local_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (std.c.getsockname(client, @ptrCast(&local), &local_len) != 0) return error.GetSockName;
    var fd: posix.socket_t = 0;
    while (fd < 4096) : (fd += 1) {
        if (fd == client) continue;
        var peer: posix.sockaddr.storage = undefined;
        var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        // Raw: posix.getpeername treats a descriptor that isn't open as unreachable.
        if (std.c.getpeername(fd, @ptrCast(&peer), &peer_len) != 0) continue;
        if (peer_len == local_len and std.mem.eql(u8, std.mem.asBytes(&peer)[0..peer_len], std.mem.asBytes(&local)[0..local_len])) return fd;
    }
    return error.ServerSocketNotFound;
}

test "Server: on Darwin, every socket it accepts has SO_NOSIGPIPE set" {
    // Through the real accept path (Blocking or NonBlocking, by build mode).
    if (comptime !builtin.os.tag.isDarwin()) return error.SkipZigTest;
    const stream = try testStream(true);
    defer stream.close();
    const server_socket = try serverSocketOf(stream.handle);
    var value: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);
    try t.expectEqual(0, std.c.getsockopt(server_socket, posix.SOL.SOCKET, posix.SO.NOSIGPIPE, @ptrCast(&value), &len));
    try t.expectEqual(true, value != 0);
}

test "setConnectionOption: a socket its peer has already reset is an error on Darwin, not a panic" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var pair = t.SocketPair.init(.{});
    defer pair.writer.deinit();
    defer pair.server.close();
    socket_wait.closeSocket(pair.client.handle, true);
    std.Thread.sleep(20 * std.time.ns_per_ms);
    const timeout = socketTimeout(5);
    const result = setConnectionOption(pair.server.handle, SOL_SOCKET, SO_SNDTIMEO, &timeout);
    if (comptime builtin.os.tag.isDarwin()) {
        try t.expectError(error.ConnectionResetByPeer, result);
    } else {
        // Linux sets options on a reset socket without complaint.
        try result;
    }
}

test "preHandOffWrite: a client that has already reset its connection is no panic" {
    // Darwin fails setsockopt on such a socket with EINVAL. A child, so
    // that a panic fails the test rather than the test run.
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const outcome = try runWithDefaultSigpipe(struct {
        fn body() !void {
            const pair = t.SocketPair.init(.{});
            var conn = try testConn(pair.server);
            socket_wait.closeSocket(pair.client.handle, true);
            std.Thread.sleep(20 * std.time.ns_per_ms);
            preHandOffWrite(&conn, "HTTP/1.1 400 \r\nConnection: Close\r\n\r\n");
        }
    }.body);
    try t.expectEqual(SigpipeOutcome{ .exited = 0 }, outcome);
}

test "suppressSigpipe: a socket its peer has already reset is no error" {
    // As when a client gives up before its connection is accepted.
    if (comptime !builtin.os.tag.isDarwin()) return error.SkipZigTest;
    var pair = t.SocketPair.init(.{});
    defer pair.writer.deinit();
    defer pair.server.close();
    socket_wait.closeSocket(pair.client.handle, true);
    std.Thread.sleep(20 * std.time.ns_per_ms);
    suppressSigpipe(pair.server.handle);
}

test "Server: a handler's handshakeErrorResponse is what a refused upgrade gets" {
    const H = struct {
        pub fn init(_: *const Handshake, _: *Conn, _: void) !@This() {
            return error.Refused;
        }
        pub fn handshakeErrorResponse(err: anyerror) []const u8 {
            std.debug.assert(err == error.Refused);
            return "HTTP/1.1 403 \r\nConnection: Close\r\nContent-Length: 0\r\n\r\n";
        }
        pub fn clientMessage(_: *@This(), _: []const u8) !void {}
    };
    var server = try Server(H).init(t.allocator, .{ .port = 9293, .address = "127.0.0.1" });
    defer server.deinit();
    const thread = try server.listenInNewThread({});
    defer {
        server.stop();
        thread.join();
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 9293);
    const stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    try stream.writeAll("GET / HTTP/1.1\r\ncontent-length: 0\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nconnection: upgrade\r\nsec-websocket-key: my-key\r\n\r\n");
    var buf: [256]u8 = undefined;
    var pos: usize = 0;
    while (pos < buf.len) {
        const n = try testRecv(stream, buf[pos..]);
        if (n == 0) break;
        pos += n;
    }
    try t.expectString("HTTP/1.1 403 \r\nConnection: Close\r\nContent-Length: 0\r\n\r\n", buf[0..pos]);
}

// The test client's reads: net.Stream.read is ReadFile on Windows in Zig 0.15,
// which fails on sockets; recv doesn't.
fn testRecv(stream: net.Stream, buf: []u8) !usize {
    return posix.recv(stream.handle, buf, 0);
}

fn testRecvAtLeast(stream: net.Stream, buf: []u8, len: usize) !usize {
    var pos: usize = 0;
    while (pos < len) {
        const n = try testRecv(stream, buf[pos..]);
        if (n == 0) return error.EndOfStream;
        pos += n;
    }
    return pos;
}

fn testStream(handshake: bool) !net.Stream {
    // 20 ms: a timeval, except on Windows, where it's a DWORD of milliseconds.
    const timeout = if (builtin.os.tag == .windows)
        std.mem.toBytes(@as(u32, 20))
    else
        std.mem.toBytes(std.posix.timeval{ .sec = 0, .usec = 20_000 });
    const address = try std.net.Address.parseIp("127.0.0.1", 9292);
    const stream = try std.net.tcpConnectToAddress(address);
    try std.posix.setsockopt(stream.handle, SOL_SOCKET, SO_RCVTIMEO, &timeout);
    try std.posix.setsockopt(stream.handle, SOL_SOCKET, SO_SNDTIMEO, &timeout);

    if (handshake == false) {
        return stream;
    }

    try stream.writeAll("GET / HTTP/1.1\r\ncontent-length: 0\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nconnection: upgrade\r\nsec-websocket-key: my-key\r\n\r\n");
    var buf: [1024]u8 = undefined;
    var pos: usize = 0;
    while (pos < buf.len) {
        const n = try testRecv(stream, buf[0..]);
        if (n == 0) break;

        pos += n;
        if (std.mem.endsWith(u8, buf[0..pos], "\r\n\r\n")) {
            break;
        }
    } else {
        unreachable;
    }

    try t.expectString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-Websocket-Accept: L8KGBs4w2MNLLzhfzlVoM0scCIE=\r\n\r\n", buf[0..pos]);

    return stream;
}

const TestHandler = struct {
    conn: *Conn,

    pub fn init(h: *const Handshake, conn: *Conn, _: void) !TestHandler {
        try t.expectString("upgrade", h.headers.get("connection").?);
        return .{
            .conn = conn,
        };
    }
    pub fn clientMessage(
        self: *TestHandler,
        allocator: Allocator,
        data: []const u8,
    ) !void {
        if (std.mem.eql(u8, data, "over")) {
            return self.conn.writeText("9000");
        }
        if (std.mem.eql(u8, data, "dyn")) {
            return self.conn.writeText(try std.fmt.allocPrint(allocator, "over {d}!", .{9000}));
        }
        if (std.mem.eql(u8, data, "writer")) {
            var wb = self.conn.writeBuffer(allocator, .text);
            try wb.interface.print("{d}!!!", .{9000});
            return wb.send();
        }
        if (std.mem.eql(u8, data, "ping")) {
            var buf = [_]u8{ 'a', '-', 'p', 'i', 'n', 'g' };
            return self.conn.writePing(&buf);
        }
        if (std.mem.eql(u8, data, "pong")) {
            var buf = [_]u8{ 'a', '-', 'p', 'o', 'n', 'g' };
            return self.conn.writePong(&buf);
        }
        if (std.mem.eql(u8, data, "close1")) {
            return self.conn.close(.{});
        }
        if (std.mem.eql(u8, data, "close2")) {
            return self.conn.close(.{ .code = 123 });
        }
        if (std.mem.eql(u8, data, "close3")) {
            return self.conn.close(.{ .code = 234, .reason = "bye" });
        }
    }
};

test "List" {
    var list = List(TestNode){};
    try expectList(&.{}, list);

    var n1 = TestNode{ .id = 1 };
    list.insert(&n1);
    try expectList(&.{1}, list);

    list.remove(&n1);
    try expectList(&.{}, list);

    var n2 = TestNode{ .id = 2 };
    list.insert(&n2);
    list.insert(&n1);
    try expectList(&.{ 2, 1 }, list);

    var n3 = TestNode{ .id = 3 };
    list.insert(&n3);
    try expectList(&.{ 2, 1, 3 }, list);

    list.remove(&n1);
    try expectList(&.{ 2, 3 }, list);

    list.insert(&n1);
    try expectList(&.{ 2, 3, 1 }, list);

    list.remove(&n2);
    try expectList(&.{ 3, 1 }, list);

    list.remove(&n1);
    try expectList(&.{3}, list);

    list.remove(&n3);
    try expectList(&.{}, list);
}

const TestNode = struct {
    id: i32,
    next: ?*TestNode = null,
    prev: ?*TestNode = null,
};

fn expectList(expected: []const i32, list: List(TestNode)) !void {
    if (expected.len == 0) {
        try t.expectEqual(null, list.head);
        try t.expectEqual(null, list.tail);
        return;
    }

    var i: usize = 0;
    var next = list.head;
    while (next) |node| {
        try t.expectEqual(expected[i], node.id);
        i += 1;
        next = node.next;
    }
    try t.expectEqual(expected.len, i);

    i = expected.len;
    var prev = list.tail;
    while (prev) |node| {
        i -= 1;
        try t.expectEqual(expected[i], node.id);
        prev = node.prev;
    }
    try t.expectEqual(0, i);
}

// Blocking-mode tests: a connection as httpz drives one (Worker.createConn,
// then readLoop on the connection's own thread).
const BlockingTest = struct {
    const Record = struct {
        closes: std.atomic.Value(u32) = .init(0),
        close_thread: std.atomic.Value(std.Thread.Id) = .init(0),
        open_at_close: std.atomic.Value(bool) = .init(false),
    };

    const Handler = struct {
        conn: *Conn,
        record: *Record,
        pub fn clientMessage(_: *@This(), _: []const u8) !void {}
        pub fn close(self: *@This()) void {
            _ = self.record.closes.fetchAdd(1, .acq_rel);
            self.record.close_thread.store(std.Thread.getCurrentId(), .release);
            self.record.open_at_close.store(!self.conn.isClosed(), .release);
        }
    };

    state: WorkerState,
    worker: Blocking(Handler),
    pair: t.SocketPair,
    hc: *HandlerConn(Handler),
    record: Record = .{},
    owner: ?std.Thread = null,
    owner_done: std.Thread.ResetEvent = .{},

    // Heap-allocated: the worker's Stop and the record must not move.
    fn init() !*BlockingTest {
        const self = try t.allocator.create(BlockingTest);
        errdefer t.allocator.destroy(self);
        self.* = .{ .state = undefined, .worker = undefined, .pair = t.SocketPair.init(.{}), .hc = undefined };
        self.state = try WorkerState.init(t.allocator, .{});
        self.worker = try Blocking(Handler).init(t.allocator, &self.state);
        self.hc = try self.worker.conn_manager.create(self.pair.server.handle, try net.Address.parseIp("127.0.0.1", 0), 0);
        self.hc.handler = .{ .conn = &self.hc.conn, .record = &self.record };
        return self;
    }

    fn startReadLoop(self: *BlockingTest) !void {
        self.owner = try std.Thread.spawn(.{}, struct {
            fn run(s: *BlockingTest) void {
                s.worker.readLoop(s.hc) catch {};
                s.owner_done.set();
            }
        }.run, .{self});
    }

    // Fails if the read loop doesn't end within `ns`; wakes it from the
    // peer's side first, so the test ends either way.
    fn expectReadLoopEnds(self: *BlockingTest, ns: u64) !void {
        self.owner_done.timedWait(ns) catch {
            posix.shutdown(self.pair.client.handle, .both) catch {};
            self.owner.?.join();
            self.owner = null;
            return error.ReadLoopKeptWaiting;
        };
        self.owner.?.join();
        const owner_id = self.record.close_thread.load(.acquire);
        self.owner = null;
        try t.expectEqual(1, self.record.closes.load(.acquire));
        try t.expectEqual(false, owner_id == std.Thread.getCurrentId());
    }

    // The peer reads until the server's side has ended: true if it was
    // reset (an abortive close), false if it was closed gracefully.
    fn peerSeesEnd(self: *BlockingTest) !bool {
        var buf: [64 * 1024]u8 = undefined;
        const deadline = std.time.milliTimestamp() + 5000;
        while (std.time.milliTimestamp() < deadline) {
            const n = testRecv(self.pair.client, &buf) catch |err| switch (err) {
                error.ConnectionResetByPeer => return true,
                error.WouldBlock => continue,
                else => return err,
            };
            if (n == 0) return false;
        }
        return error.PeerNeverSawTheEnd;
    }

    fn deinit(self: *BlockingTest) void {
        if (self.owner) |o| o.join();
        self.worker.deinit();
        self.state.deinit();
        self.pair.deinit();
        t.allocator.destroy(self);
    }
};

test "Blocking: stopping wakes a connection waiting for data, which ends on its own thread with its socket still open for the handler's close" {
    if (comptime !blockingMode()) return error.SkipZigTest;
    var bt = try BlockingTest.init();
    defer bt.deinit();
    try bt.startReadLoop();
    std.Thread.sleep(50 * std.time.ns_per_ms);

    const started = std.time.milliTimestamp();
    bt.worker.shutdown();
    try bt.expectReadLoopEnds(2 * std.time.ns_per_s);
    try t.expectEqual(true, std.time.milliTimestamp() - started < 500);
    try t.expectEqual(true, bt.record.open_at_close.load(.acquire));
    _ = try bt.peerSeesEnd();
}

test "Blocking: a connection whose read loop starts after stopping ends without waiting" {
    if (comptime !blockingMode()) return error.SkipZigTest;
    var bt = try BlockingTest.init();
    defer bt.deinit();
    bt.worker.shutdown();
    try bt.startReadLoop();
    try bt.expectReadLoopEnds(2 * std.time.ns_per_s);
    _ = try bt.peerSeesEnd();
}

test "Blocking: a writer to a peer that stopped reading never waits, and the connection is reset on its own thread" {
    if (comptime !blockingMode()) return error.SkipZigTest;
    var bt = try BlockingTest.init();
    defer bt.deinit();
    try setSendBuffer(bt.pair.server.handle, 16 * 1024);
    try bt.startReadLoop();

    const Writer = struct {
        conn: *Conn,
        failed: ?anyerror = null,
        slowest_ms: i64 = 0,
        done: std.Thread.ResetEvent = .{},

        fn run(w: *@This()) void {
            defer w.done.set();
            var payload: [256 * 1024]u8 = undefined;
            @memset(&payload, 'x');
            for (0..(Conn.max_pending_bytes / payload.len) * 4) |_| {
                const started = std.time.milliTimestamp();
                w.conn.writeBin(&payload) catch |err| {
                    w.failed = err;
                    return;
                };
                w.slowest_ms = @max(w.slowest_ms, std.time.milliTimestamp() - started);
            }
        }
    };
    // The peer never reads.
    var writer = Writer{ .conn = &bt.hc.conn };
    const thread = try std.Thread.spawn(.{}, Writer.run, .{&writer});
    writer.done.timedWait(10 * std.time.ns_per_s) catch {
        // Blocked in send: free it from the peer's side, then fail.
        posix.shutdown(bt.pair.client.handle, .both) catch {};
        thread.join();
        return error.WriterBlocked;
    };
    thread.join();

    try t.expectEqual(true, writer.failed != null);
    try t.expectEqual(true, writer.slowest_ms < 1000);
    try bt.expectReadLoopEnds(2 * std.time.ns_per_s);
    try t.expectEqual(true, try bt.peerSeesEnd());
}

test "Blocking: a close frame written on the connection's own thread reaches the peer before a graceful close" {
    if (comptime !blockingMode()) return error.SkipZigTest;
    var bt = try BlockingTest.init();
    defer bt.deinit();

    // As a handler refusing a client does it (REAmo, from its init), then
    // as httpz cleans the connection up.
    try bt.hc.conn.close(.{ .code = 4500, .reason = "full" });
    try t.expectError(error.Closed, bt.hc.conn.writeText("after the close"));
    bt.worker.cleanupConn(bt.hc);

    var buf: [8]u8 = undefined;
    _ = try testRecvAtLeast(bt.pair.client, &buf, 8);
    try t.expectSlice(u8, &.{ 0x88, 6, 0x11, 0x94, 'f', 'u', 'l', 'l' }, &buf);
    try t.expectEqual(1, bt.record.closes.load(.acquire));
    try t.expectEqual(false, try bt.peerSeesEnd());
}

test "Blocking: writers racing the connection's close never use its socket after it" {
    if (comptime !blockingMode()) return error.SkipZigTest;
    for (0..100) |i| {
        var bt = try BlockingTest.init();
        defer bt.deinit();
        const Hammer = struct {
            fn run(conn: *Conn) void {
                while (true) {
                    conn.writeText("x") catch return;
                    // Windows' locks aren't fair: a writer that never lets
                    // go would hold the close off for a long while.
                    std.Thread.yield() catch {};
                }
            }
        };
        const thread = try std.Thread.spawn(.{}, Hammer.run, .{&bt.hc.conn});
        if (i % 2 == 0) std.Thread.sleep(std.time.ns_per_ms);
        // The connection's own thread closes it while the hammer writes.
        bt.hc.conn.release();
        thread.join();
        bt.worker.cleanupConn(bt.hc);
    }
}

test "Server: a client that never sends a handshake is dropped at the handshake timeout" {
    const H = struct {
        pub fn init(_: *const Handshake, _: *Conn, _: void) !@This() {
            return .{};
        }
        pub fn clientMessage(_: *@This(), _: []const u8) !void {}
    };
    var server = try Server(H).init(t.allocator, .{ .port = 9294, .address = "127.0.0.1", .handshake = .{ .timeout = 1 } });
    defer server.deinit();
    const thread = try server.listenInNewThread({});
    defer {
        server.stop();
        thread.join();
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 9294);
    const stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    const started = std.time.milliTimestamp();
    var buf: [16]u8 = undefined;
    const n = testRecv(stream, &buf) catch |err| switch (err) {
        error.ConnectionResetByPeer => 0,
        else => return err,
    };
    const waited = std.time.milliTimestamp() - started;
    try t.expectEqual(0, n);
    try t.expectEqual(true, waited >= 900 and waited < 3000);
}
