pub mod fd_revoker;
pub mod monitor;
pub mod policy_loader;
pub mod policy_source;
pub mod stream_attributes;
pub mod time;

pub const TAIL_IDX_FILE_OPEN_STATIC: u32 = 0;
pub const TAIL_IDX_FILE_OPEN_STREAM: u32 = 1;
pub const TAIL_IDX_FILE_OPEN_COMBINE: u32 = 2;
pub const TAIL_IDX_SOCKET_BIND_STATIC: u32 = 0;
pub const TAIL_IDX_SOCKET_BIND_STREAM: u32 = 1;
pub const TAIL_IDX_SOCKET_BIND_COMBINE: u32 = 2;
pub const BPF_PIN_DIRECTORY: &str = "/sys/fs/bpf/tails-pdp";

pub struct LsmProgramSpec {
    pub name: &'static str,
    pub hook: &'static str,
    pub attach: bool,
}

pub const LSM_PROGRAMS: [LsmProgramSpec; 8] = [
    LsmProgramSpec {
        name: "file_open",
        hook: "file_open",
        attach: true,
    },
    LsmProgramSpec {
        name: "evaluate_file_open_static_policies",
        hook: "file_open",
        attach: false,
    },
    LsmProgramSpec {
        name: "evaluate_file_open_stream_policies",
        hook: "file_open",
        attach: false,
    },
    LsmProgramSpec {
        name: "combine_file_open",
        hook: "file_open",
        attach: false,
    },
    LsmProgramSpec {
        name: "socket_bind",
        hook: "socket_bind",
        attach: true,
    },
    LsmProgramSpec {
        name: "evaluate_socket_bind_static_policies",
        hook: "socket_bind",
        attach: false,
    },
    LsmProgramSpec {
        name: "evaluate_socket_bind_stream_policies",
        hook: "socket_bind",
        attach: false,
    },
    LsmProgramSpec {
        name: "combine_socket_bind",
        hook: "socket_bind",
        attach: false,
    },
];

pub const FILE_OPEN_TAIL_PROGRAMS: [(u32, &str); 3] = [
    (
        TAIL_IDX_FILE_OPEN_STATIC,
        "evaluate_file_open_static_policies",
    ),
    (
        TAIL_IDX_FILE_OPEN_STREAM,
        "evaluate_file_open_stream_policies",
    ),
    (TAIL_IDX_FILE_OPEN_COMBINE, "combine_file_open"),
];

pub const SOCKET_BIND_TAIL_PROGRAMS: [(u32, &str); 3] = [
    (
        TAIL_IDX_SOCKET_BIND_STATIC,
        "evaluate_socket_bind_static_policies",
    ),
    (
        TAIL_IDX_SOCKET_BIND_STREAM,
        "evaluate_socket_bind_stream_policies",
    ),
    (TAIL_IDX_SOCKET_BIND_COMBINE, "combine_socket_bind"),
];
