pub mod policy_loader;
pub mod time;

pub const TAIL_IDX_FILE_OPEN_STATIC: u32 = 0;
pub const TAIL_IDX_FILE_OPEN_STREAM: u32 = 1;
pub const TAIL_IDX_COMBINE: u32 = 2;
pub const BPF_PIN_DIRECTORY: &str = "/sys/fs/bpf/tails-pdp";

pub struct LsmProgramSpec {
    pub name: &'static str,
    pub hook: &'static str,
    pub attach: bool,
}

pub const LSM_PROGRAMS: [LsmProgramSpec; 5] = [
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
        name: "combine",
        hook: "file_open",
        attach: false,
    },
    LsmProgramSpec {
        name: "socket_bind",
        hook: "socket_bind",
        attach: true,
    },
];

pub const TAIL_PROGRAMS: [(u32, &str); 3] = [
    (
        TAIL_IDX_FILE_OPEN_STATIC,
        "evaluate_file_open_static_policies",
    ),
    (
        TAIL_IDX_FILE_OPEN_STREAM,
        "evaluate_file_open_stream_policies",
    ),
    (TAIL_IDX_COMBINE, "combine"),
];
