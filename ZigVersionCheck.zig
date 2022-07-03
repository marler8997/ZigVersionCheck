//! This file is hosted at github.com/marler8997/ZigVersionCheck and is meant to be copied
//! to projects that use it.
//!
//! How to create a zig version string.
//!
//! A zig version number typically of the form:
//!
//!     <next_tag>-dev-<commit_height>-<partial_hash>
//!
//! next_tag wil be something like "0.10.0"
//! the rest of the version can be obtained with the following steps:
//! 1. Identify the commit
//! 2. Obtain the commit_height
//!     2a. Checkout that revision in a git repository
//!     2b. Run "git describe" which will output <parent_tag>-<commit_height>-g<hash>
//!         i.e. 0.9.0-2412-g4e918873e, in this case the commit_height is 2412
//!
//! For example, if `git describe` prints `0.9.0-2412-g4e918873e`, then the zig version would be:
//!
//!    0.10.0-dev-2412-4e918873e
//!
//! NOTE: the main difference between the two are that the tag went from '0.9.0' to '0.10.0-dev' and
//!       the 'g' prefix was removed from the hash
//!
const std = @import("std");
const ZigVersionCheck = @This();

pub const Enforce = enum { none, warn, err };

pub const Compare = enum {
    equal,
    less_than,
    greater_than,
    commit_height_equal,
    commit_height_less_than,
    commit_height_greater_than,
};
const Version = struct {
    major: u16,
    minor: u16,
    patch: u16,
    dev: bool,
    git_info: ?GitInfo,

    pub const GitInfo = struct {
        commit_height: u32,
        sha_buf: [40]u8,
        sha_len: u8,
        pub fn sha(self: *const GitInfo) []const u8 {
            return self.sha_buf[0 .. self.sha_len];
        }
    };

    pub fn compare(self: Version, right: Version) Compare {
        if (self.dev != right.dev) {
            std.debug.panic("TODO: implement comparing dev to non-dev versions '{}' and '{}'", .{self, right});
        }
        if (self.major != right.major) return if (self.major > right.major) .greater_than else .less_than;
        if (self.minor != right.minor) return if (self.minor > right.minor) .greater_than else .less_than;
        if (self.patch != right.patch) return if (self.patch > right.patch) .greater_than else .less_than;

        if (self.git_info) |self_git_info| {
            // NOTE: using the commit_height doesn't
            const right_git_info = right.git_info orelse return .commit_height_greater_than;
            if (self_git_info.commit_height > right_git_info.commit_height)
                return .commit_height_greater_than;
            if (self_git_info.commit_height < right_git_info.commit_height)
                return .commit_height_less_than;
            if (!std.mem.eql(u8, self_git_info.sha(), right_git_info.sha()))
                return .commit_height_equal;
        }
        if (right.git_info) |_| return .commit_height_less_than;
        return .equal;
    }

    fn compareIntAssumeNotEqual(comptime T: type, left: T, right: T) Compare {
        std.debug.assert(left != right);
        return if (left > right) .greater_than else .less_than;
    }

    pub fn format(
        self: Version,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        var git_str_buf: [60]u8 = undefined;
        const git_str: []const u8 = blk: {
            if (self.git_info) |git_info| {
                break :blk std.fmt.bufPrint(&git_str_buf, ".{d}+{s}", .{git_info.commit_height, git_info.sha()}) catch unreachable;
            }
            break :blk "";
        };
        const dev_str: []const u8 = if (self.dev) "-dev" else "";
        try writer.print("{}.{}.{}{s}{s}", .{self.major, self.minor, self.patch, dev_str, git_str});
    }
};

step: std.build.Step,
builder: *std.build.Builder,
min: ?Version,
// Max version would be more difficult to implement correctly.  It would require a mechanism
// to obtain a list of all the known SHA's since the specified max version.
// This is because the only thing we really know is the "commit_height" since the last tag, however,
// we don't know where the current compiler has branched from the master branch, so the commit height
// doesn't tell us if it includes the change that we know breaks us.  To know for sure, we would
// have to get a list of all the commits since our max version.  If the sha of the current compiler
// does not match any of them, then we know its merge base was before our max version so it is OK.
// For now I'm just not going to implement max version checking.  Also note that the other way to
// solve this is to know if the current zig compiler is from master or another branch.
//max: ?Version,
enforce: Enforce,

pub fn create(b: *std.build.Builder, opt: struct {
    min: ?Version,
    //max: ?Version,
    enforce: Enforce = .err,
}) *ZigVersionCheck {
    var result = b.allocator.create(ZigVersionCheck) catch @panic("OutOfMemory");
    result.* = ZigVersionCheck{
        .step = std.build.Step.init(.custom, "check the zig compiler version", b.allocator, make),
        .builder = b,
        .min = opt.min,
        //.max = opt.max,
        .enforce = opt.enforce,
    };
    return result;
}

fn enforceLog(self: ZigVersionCheck, comptime format: []const u8, arg: anytype) void {
    switch (self.enforce) {
        .none => unreachable,
        .warn => std.log.warn(format, arg),
        .err => std.log.err(format, arg),
    }
}

fn make(step: *std.build.Step) !void {
    const self = @fieldParentPtr(ZigVersionCheck, "step", step);
    const result = try std.ChildProcess.exec(.{
        .allocator = self.builder.allocator, 
        .argv = &[_][]const u8 { self.builder.zig_exe, "version" },
    });
    if (result.stderr.len > 0) {
        std.log.err("zig version stderr: '{s}'", .{result.stderr});
    }
    switch (result.term) {
        .Exited => |code| {
            if (code != 0) {
                self.enforceLog("'zig version' process exited with code '{}'", .{code});
                return if (self.enforce == .err) std.os.exit(0xff);
            }
        },
        else => {
            self.enforceLog("'zig version' process terminated (result={})", .{result.term});
            if (self.enforce == .err) std.os.exit(0xff);
            return;
        },
    }
    const version_str = std.mem.trimRight(u8, result.stdout, "\r\n");
    const version = parse(version_str) catch |err| {
        self.enforceLog("failed to parse output of zig version '{s}' with {s}", .{version_str, @errorName(err)});
        if (self.enforce == .err) std.os.exit(0xff);
        return;
    };

    if (self.min) |min| {
        switch (version.compare(min)) {
            .equal,
            .greater_than,
            .commit_height_greater_than,
            => {},
            .less_than,
            .commit_height_equal,
            .commit_height_less_than,
            => {
                self.enforceLog("zig version '{s}' is too old, min is '{s}'", .{version, min});
                if (self.enforce == .err) std.os.exit(0xff);
                return;
            },
        }
    }
}

pub const ParseZigVersionError = error {
    InvalidMajorVersion,
    MissingMinorVersion,
    InvalidMinorVersion,
    MissingPatchVersion,
    InvalidPatchVersion,
    InvalidCommitHeight,
    MissingHashSuffix,
    HashSuffixTooLong,
    TooManyDotSeparators,
};
pub fn parse(version: []const u8) ParseZigVersionError!Version {
    var dot_it = std.mem.split(u8, version, ".");
    const major = std.fmt.parseInt(u16, dot_it.next().?, 10) catch return error.InvalidMajorVersion;
    const minor = std.fmt.parseInt(u16, dot_it.next() orelse return error.MissingMinorVersion, 10)
        catch return error.InvalidMinorVersion;
    var patch_str = dot_it.next() orelse return error.MissingPatchVersion;
    var dev = false;
    if (std.mem.endsWith(u8, patch_str, "-dev")) {
        patch_str = patch_str[0 .. patch_str.len - "-dev".len];
        dev = true;
    }
    const patch = std.fmt.parseInt(u16, patch_str , 10) catch return error.InvalidPatchVersion;

    var git_info: ?Version.GitInfo = null;
    if (dot_it.next()) |git_info_str| {
        var plus_it = std.mem.split(u8, git_info_str, "+");
        var commit_height = std.fmt.parseInt(u32, plus_it.next().?, 10) catch return error.InvalidCommitHeight;
        var sha = plus_it.next() orelse return error.MissingHashSuffix;
        if (sha.len > 40) return error.HashSuffixTooLong;
        if (dot_it.next()) |_| return error.TooManyDotSeparators;
        git_info = .{
            .commit_height = commit_height,
            .sha_len = @intCast(u8, sha.len),
            .sha_buf = undefined,
        };
        std.mem.copy(u8, git_info.?.sha_buf[0 .. sha.len], sha);
    }
    return Version{
        .major = major,
        .minor = minor,
        .patch = patch,
        .dev = dev,
        .git_info = git_info,
    };
}
