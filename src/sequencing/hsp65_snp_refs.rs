// hsp65 diagnostic-SNP reference data, shared by the crate (declared as
// `sequencing::hsp65_snp_refs`) and `build.rs` (pulled in with `include!`, where
// `check_hsp65_integrity()` validates it against the built `myco_hsp65.fasta`).
//
// Keep this file to plain `const`/`struct` items: no `use`, no `crate::`/`super::` paths and
// no inner `//!` doc comments, so it compiles unchanged in both places.

/// One GenBank hsp65 partial-cds entry whose coordinate system a diagnostic SNP table is
/// written in.
///
/// SNP positions are 0-based offsets **into this exact entry**, as delivered by the NCBI
/// `type_material` bulk fetch (`fetch_myco_sequences()` in `build.rs`). They are *not* positions
/// in the ntm-db full-length genes or the `res/sequences/references/` amplicons. A read that
/// best matches any other reference gets no SNP calls, even if it is the same species.
pub struct Hsp65SnpRef {
    /// GenBank accession without version suffix (e.g. `"AF547836"`).
    pub accession: &'static str,
    /// `Genus species` as `parse_multi_fasta()` derives it from the FASTA header.
    pub species: &'static str,
    /// Expected sequence length in `myco_hsp65.fasta`; guards against NCBI record revisions
    /// silently shifting the coordinate system.
    pub len: usize,
}

/// A species pair that hsp65 identity alone cannot separate, plus the diagnostic positions
/// that can.
pub struct Hsp65SnpPair {
    /// The two references; `snps[i].1` is the allele of `refs[0]`, `snps[i].2` that of `refs[1]`.
    pub refs: [Hsp65SnpRef; 2],
    /// `(0-based position in either reference, allele of refs[0], allele of refs[1])`.
    /// Both references share one coordinate system (same amplicon, no indels between them).
    pub snps: &'static [(usize, u8, u8)],
}

pub const ACC_GASTRI: &str = "AF547836";
pub const ACC_KANSASII: &str = "AF547849";
pub const ACC_MARINUM: &str = "AY299134";
pub const ACC_ULCERANS: &str = "AY299145";

/// *M. gastri* (CIP 104530, `AF547836`) vs *M. kansasii* (CIP 104589, `AF547849`).
pub const KANSASII_GASTRI: Hsp65SnpPair = Hsp65SnpPair {
    refs: [
        Hsp65SnpRef {
            accession: ACC_GASTRI,
            species: "Mycobacterium gastri",
            len: 424,
        },
        Hsp65SnpRef {
            accession: ACC_KANSASII,
            species: "Mycobacterium kansasii",
            len: 424,
        },
    ],
    // (0-based ref pos, gastri_base, kansasii_base)
    snps: &[
        (100, b'C', b'T'),
        (130, b'C', b'T'),
        (148, b'G', b'A'),
        (193, b'G', b'C'),
        (283, b'C', b'G'),
        (304, b'T', b'C'),
        (349, b'G', b'C'),
        (400, b'G', b'A'),
    ],
};

/// *M. marinum* (ATCC 927, `AY299134`) vs *M. ulcerans* (ATCC 19423, `AY299145`).
pub const MARINUM_ULCERANS: Hsp65SnpPair = Hsp65SnpPair {
    refs: [
        Hsp65SnpRef {
            accession: ACC_MARINUM,
            species: "Mycobacterium marinum",
            len: 603,
        },
        Hsp65SnpRef {
            accession: ACC_ULCERANS,
            species: "Mycobacterium ulcerans",
            len: 603,
        },
    ],
    // (0-based ref pos, marinum_base, ulcerans_base)
    snps: &[
        (20, b'C', b'T'),
        (204, b'T', b'C'),
        (212, b'G', b'A'),
        (482, b'T', b'C'),
        (500, b'G', b'C'),
    ],
};

/// Every hsp65 SNP-reference pair; `build.rs` validates all of them.
pub const HSP65_SNP_PAIRS: &[&Hsp65SnpPair] = &[&KANSASII_GASTRI, &MARINUM_ULCERANS];
