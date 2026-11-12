//! ==============================================================================
//! Product:       Logihertz dm-verity Builder (lh-dmverity)
//! Module:        main.rs
//! Role:          CLI Entry Point & Subcommand Router
//! Organization:  Logihertz Systems (OPC) Private Limited
//! Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
//! Contact:       ops@logihertz.com / security@logihertz.com
//! License:       Apache-2.0
//! ==============================================================================

use lh_dmverity_builder::auditor::audit_policy;
use lh_dmverity_builder::exporters::{format_json, format_sarif, format_table};
use lh_dmverity_builder::json::JsonValue;
use lh_dmverity_builder::merkle::MerkleTree;
use lh_dmverity_builder::sha256::{hex_decode, hex_encode};
use lh_dmverity_builder::superblock::{format_dm_table, format_kernel_cmdline, VeritySuperblock};

use std::env;
use std::fs;
use std::process;

const VERSION: &str = "0.1.0";
const DEFAULT_SALT_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn print_usage() {
    println!(
        r#"lh-dmverity {version} - Cryptographic dm-verity Merkle Tree Builder & Posture Auditor
Logihertz Systems (OPC) Private Limited
Creator & Developer: Sameer Tawade <ops@logihertz.com>

USAGE:
    lh-dmverity <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    scan <manifest.json>       Audit immutable rootfs security policy against 10 rules
    build-tree <image_path>    Construct hierarchical Merkle tree and compute root hash
    verify-tree <image_path>   Verify filesystem against expected root hash
    gen-table <image_path>     Generate device-mapper table and kernel bootline
    help, --help, -h           Print this help message
    version, --version, -V     Print version information

OPTIONS for 'scan':
    --format <table|json|sarif> Output format (default: table)
    --output <file_path>        Write report to file instead of stdout

OPTIONS for 'build-tree':
    --salt <hex>               Cryptographic salt in hex (default: SHA-256 standard salt)
    --output-tree <path>       Write serialized hash tree binary to file
    --superblock <path>        Write 512-byte dm-verity on-disk superblock to file

OPTIONS for 'verify-tree':
    --root-hash <hex>          Expected 32-byte Merkle root hash in hex (REQUIRED)
    --salt <hex>               Cryptographic salt in hex

OPTIONS for 'gen-table':
    --data-dev <path>          Path to underlying data device (e.g. /dev/mmcblk0p2)
    --hash-dev <path>          Path to hash tree device (e.g. /dev/mmcblk0p3)
    --salt <hex>               Cryptographic salt in hex
    --root-hash <hex>          Pre-computed root hash (optional)

EXIT CODES:
    0    Clean scan (Score: 100) or successful root hash verification
    1    Posture violation detected or root hash mismatch
    2    Invalid CLI usage or missing file"#,
        version = VERSION
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        process::exit(2);
    }

    match args[1].as_str() {
        "-h" | "--help" | "help" => {
            print_usage();
            process::exit(0);
        }
        "-V" | "--version" | "version" => {
            println!(
                "lh-dmverity {} (Logihertz Systems - Sameer Tawade)",
                VERSION
            );
            process::exit(0);
        }
        "scan" => handle_scan(&args[2..]),
        "build-tree" => handle_build_tree(&args[2..]),
        "verify-tree" => handle_verify_tree(&args[2..]),
        "gen-table" => handle_gen_table(&args[2..]),
        unknown => {
            eprintln!(
                "[ERROR] Unknown subcommand '{}'. Run 'lh-dmverity --help' for usage.",
                unknown
            );
            process::exit(2);
        }
    }
}

fn handle_scan(args: &[String]) {
    if args.is_empty() {
        eprintln!("[ERROR] Missing manifest path. Usage: lh-dmverity scan <manifest.json> [--format table|json|sarif]");
        process::exit(2);
    }

    let manifest_path = &args[0];
    let mut format = "table";
    let mut output_path: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                if i + 1 >= args.len() {
                    eprintln!("[ERROR] --format requires an argument (table, json, or sarif)");
                    process::exit(2);
                }
                format = args[i + 1].as_str();
                i += 2;
            }
            "--output" => {
                if i + 1 >= args.len() {
                    eprintln!("[ERROR] --output requires a file path argument");
                    process::exit(2);
                }
                output_path = Some(args[i + 1].as_str());
                i += 2;
            }
            other => {
                eprintln!("[ERROR] Unknown scan option '{}'", other);
                process::exit(2);
            }
        }
    }

    let raw_content = match fs::read_to_string(manifest_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[ERROR] Failed to read manifest file '{}': {}",
                manifest_path, e
            );
            process::exit(2);
        }
    };

    let policy_json = match JsonValue::parse(&raw_content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "[ERROR] Failed to parse JSON manifest '{}': {}",
                manifest_path, e
            );
            process::exit(2);
        }
    };

    let report = audit_policy(&policy_json, manifest_path);

    let output_str = match format {
        "table" => format_table(&report),
        "json" => format_json(&report),
        "sarif" => format_sarif(&report),
        unknown => {
            eprintln!(
                "[ERROR] Unsupported format '{}'. Valid formats: table, json, sarif",
                unknown
            );
            process::exit(2);
        }
    };

    if let Some(out_file) = output_path {
        if let Err(e) = fs::write(out_file, &output_str) {
            eprintln!("[ERROR] Failed to write report to '{}': {}", out_file, e);
            process::exit(2);
        }
        println!("[OK] Audit report written to '{}'", out_file);
    } else {
        println!("{}", output_str);
    }

    if report.score == 100 {
        process::exit(0);
    } else {
        process::exit(1);
    }
}

fn handle_build_tree(args: &[String]) {
    if args.is_empty() {
        eprintln!(
            "[ERROR] Missing image path. Usage: lh-dmverity build-tree <image_path> [--salt <hex>]"
        );
        process::exit(2);
    }

    let image_path = &args[0];
    let mut salt_hex = DEFAULT_SALT_HEX.to_string();
    let mut output_tree: Option<&str> = None;
    let mut output_sb: Option<&str> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--salt" => {
                if i + 1 >= args.len() {
                    eprintln!("[ERROR] --salt requires a hex string argument");
                    process::exit(2);
                }
                salt_hex = args[i + 1].clone();
                i += 2;
            }
            "--output-tree" => {
                if i + 1 >= args.len() {
                    eprintln!("[ERROR] --output-tree requires a file path argument");
                    process::exit(2);
                }
                output_tree = Some(args[i + 1].as_str());
                i += 2;
            }
            "--superblock" => {
                if i + 1 >= args.len() {
                    eprintln!("[ERROR] --superblock requires a file path argument");
                    process::exit(2);
                }
                output_sb = Some(args[i + 1].as_str());
                i += 2;
            }
            other => {
                eprintln!("[ERROR] Unknown build-tree option '{}'", other);
                process::exit(2);
            }
        }
    }

    let salt_bytes = match hex_decode(&salt_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[ERROR] Invalid salt hex string: {}", e);
            process::exit(2);
        }
    };

    let data_bytes = match fs::read(image_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[ERROR] Failed to read image file '{}': {}", image_path, e);
            process::exit(2);
        }
    };

    let tree = match MerkleTree::build(&data_bytes, &salt_bytes) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[ERROR] Failed to construct Merkle tree: {}", e);
            process::exit(2);
        }
    };

    let root_hex = hex_encode(&tree.root_hash);

    println!("\n================================================================================");
    println!(" Logihertz dm-verity Merkle Tree Construction Complete");
    println!("================================================================================");
    println!(" Data Image:       {}", image_path);
    println!(" Data Size:        {} bytes", data_bytes.len());
    println!(
        " Data Blocks:      {} (4096-byte blocks)",
        tree.data_blocks_count
    );
    println!(" Tree Levels:      {}", tree.levels.len());
    println!(
        " Total Hash Blocks:{} ({} bytes)",
        tree.total_hash_blocks(),
        tree.tree_bytes.len()
    );
    println!(" Salt:             {}", salt_hex);
    println!(" Root Hash:        {}", root_hex);
    println!("================================================================================\n");

    if let Some(tree_path) = output_tree {
        if let Err(e) = fs::write(tree_path, &tree.tree_bytes) {
            eprintln!(
                "[ERROR] Failed to write tree bytes to '{}': {}",
                tree_path, e
            );
            process::exit(2);
        }
        println!("[OK] Serialized hash tree written to '{}'", tree_path);
    }

    if let Some(sb_path) = output_sb {
        let sb = VeritySuperblock::new(tree.data_blocks_count, &salt_bytes);
        let sb_bytes = sb.serialize();
        if let Err(e) = fs::write(sb_path, sb_bytes) {
            eprintln!("[ERROR] Failed to write superblock to '{}': {}", sb_path, e);
            process::exit(2);
        }
        println!(
            "[OK] 512-byte dm-verity superblock written to '{}'",
            sb_path
        );
    }

    process::exit(0);
}

fn handle_verify_tree(args: &[String]) {
    if args.is_empty() {
        eprintln!("[ERROR] Missing image path. Usage: lh-dmverity verify-tree <image_path> --root-hash <hex>");
        process::exit(2);
    }

    let image_path = &args[0];
    let mut salt_hex = DEFAULT_SALT_HEX.to_string();
    let mut expected_root_hex: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--root-hash" => {
                if i + 1 >= args.len() {
                    eprintln!("[ERROR] --root-hash requires a 32-byte hex string argument");
                    process::exit(2);
                }
                expected_root_hex = Some(args[i + 1].clone());
                i += 2;
            }
            "--salt" => {
                if i + 1 >= args.len() {
                    eprintln!("[ERROR] --salt requires a hex string argument");
                    process::exit(2);
                }
                salt_hex = args[i + 1].clone();
                i += 2;
            }
            other => {
                eprintln!("[ERROR] Unknown verify-tree option '{}'", other);
                process::exit(2);
            }
        }
    }

    let expected_str = match expected_root_hex {
        Some(s) => s,
        None => {
            eprintln!("[ERROR] Missing required option --root-hash <hex>");
            process::exit(2);
        }
    };

    let expected_bytes = match hex_decode(&expected_str) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            eprintln!("[ERROR] Invalid --root-hash (must be 64 valid hex characters = 32 bytes)");
            process::exit(2);
        }
    };

    let salt_bytes = match hex_decode(&salt_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[ERROR] Invalid salt hex string: {}", e);
            process::exit(2);
        }
    };

    let data_bytes = match fs::read(image_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[ERROR] Failed to read image file '{}': {}", image_path, e);
            process::exit(2);
        }
    };

    let tree = match MerkleTree::build(&data_bytes, &salt_bytes) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[ERROR] Failed to construct Merkle tree: {}", e);
            process::exit(2);
        }
    };

    let computed_hex = hex_encode(&tree.root_hash);

    if tree.verify_root_hash(&expected_bytes) {
        println!(
            "[OK] dm-verity root hash MATCHES expected hash: {}",
            computed_hex
        );
        process::exit(0);
    } else {
        eprintln!("[ERROR] dm-verity root hash MISMATCH!");
        eprintln!("  Expected: {}", expected_str);
        eprintln!("  Computed: {}", computed_hex);
        process::exit(1);
    }
}

fn handle_gen_table(args: &[String]) {
    if args.is_empty() {
        eprintln!("[ERROR] Missing image path. Usage: lh-dmverity gen-table <image_path> --data-dev <path> --hash-dev <path>");
        process::exit(2);
    }

    let image_path = &args[0];
    let mut data_dev = "/dev/mmcblk0p2".to_string();
    let mut hash_dev = "/dev/mmcblk0p3".to_string();
    let mut salt_hex = DEFAULT_SALT_HEX.to_string();
    let mut precomputed_root: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dev" => {
                if i + 1 >= args.len() {
                    eprintln!("[ERROR] --data-dev requires a device path");
                    process::exit(2);
                }
                data_dev = args[i + 1].clone();
                i += 2;
            }
            "--hash-dev" => {
                if i + 1 >= args.len() {
                    eprintln!("[ERROR] --hash-dev requires a device path");
                    process::exit(2);
                }
                hash_dev = args[i + 1].clone();
                i += 2;
            }
            "--salt" => {
                if i + 1 >= args.len() {
                    eprintln!("[ERROR] --salt requires a hex string argument");
                    process::exit(2);
                }
                salt_hex = args[i + 1].clone();
                i += 2;
            }
            "--root-hash" => {
                if i + 1 >= args.len() {
                    eprintln!("[ERROR] --root-hash requires a hex string argument");
                    process::exit(2);
                }
                precomputed_root = Some(args[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!("[ERROR] Unknown gen-table option '{}'", other);
                process::exit(2);
            }
        }
    }

    let salt_bytes = match hex_decode(&salt_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[ERROR] Invalid salt hex string: {}", e);
            process::exit(2);
        }
    };

    let data_bytes = match fs::read(image_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[ERROR] Failed to read image file '{}': {}", image_path, e);
            process::exit(2);
        }
    };

    let (data_blocks, root_hex) = match precomputed_root {
        Some(r) => {
            let blocks = (data_bytes.len() as u64).div_ceil(4096);
            (blocks, r)
        }
        None => {
            let tree = match MerkleTree::build(&data_bytes, &salt_bytes) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[ERROR] Failed to build Merkle tree: {}", e);
                    process::exit(2);
                }
            };
            (tree.data_blocks_count, hex_encode(&tree.root_hash))
        }
    };

    let table_line = format_dm_table(
        0,
        &data_dev,
        &hash_dev,
        4096,
        4096,
        data_blocks,
        0,
        "sha256",
        &root_hex,
        &salt_hex,
    );
    let cmdline = format_kernel_cmdline(&table_line);

    println!("\n# Linux Device-Mapper Table Mapping:");
    println!("{}", table_line);
    println!("\n# dmsetup create command:");
    println!("dmsetup create vroot --table \"{}\"", table_line);
    println!("\n# Early-Boot Kernel Command-Line Parameter:");
    println!("{}\n", cmdline);

    process::exit(0);
}
