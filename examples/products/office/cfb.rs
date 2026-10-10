//! Compound File Binary ([MS-CFB]), the container every Office file
//! before 2007 is, and every encrypted Office file still is: a small
//! FAT file system in one file, of storages (directories) and streams.
//!
//! The file is a run of sectors, 512 bytes at version 3 and 4096 at
//! version 4, after a header that occupies the first one. A FAT chains
//! each stream's sectors; the FAT's own sectors are listed by the DIFAT,
//! whose first 109 entries are in the header. Streams shorter than 4096
//! bytes live instead in the *mini stream*, 64-byte mini sectors chained
//! by a mini FAT, which is itself stored as an ordinary stream belonging
//! to the root entry. The directory is an array of 128-byte entries;
//! each storage's children form a red-black tree ordered by name length
//! and then by upper-cased name.
//!
//! Reading takes either version and every chain is bounded, so a
//! corrupt or hostile file is an error rather than a loop. Writing
//! produces version 3.

const SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const FREESECT: u32 = 0xffff_ffff;
const ENDOFCHAIN: u32 = 0xffff_fffe;
const FATSECT: u32 = 0xffff_fffd;
const DIFSECT: u32 = 0xffff_fffc;
const NOSTREAM: u32 = 0xffff_ffff;
const MINI_CUTOFF: u64 = 4096;
const MINI_SECTOR: usize = 64;
const HEADER_DIFAT: usize = 109;

#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Storage(Storage),
    Stream(String, Vec<u8>),
}

impl Item {
    pub fn name(&self) -> &str {
        match self {
            Item::Storage(s) => &s.name,
            Item::Stream(name, _) => name,
        }
    }
}

/// A storage and what it holds, in the directory's order.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Storage {
    pub name: String,
    pub clsid: [u8; 16],
    pub children: Vec<Item>,
}

impl Storage {
    pub fn new(name: &str) -> Storage {
        Storage { name: name.to_string(), ..Storage::default() }
    }

    pub fn stream(&self, name: &str) -> Option<&Vec<u8>> {
        self.children.iter().find_map(|item| match item {
            Item::Stream(n, data) if n == name => Some(data),
            _ => None,
        })
    }

    pub fn stream_mut(&mut self, name: &str) -> Option<&mut Vec<u8>> {
        self.children.iter_mut().find_map(|item| match item {
            Item::Stream(n, data) if n == name => Some(data),
            _ => None,
        })
    }

    pub fn storage(&self, name: &str) -> Option<&Storage> {
        self.children.iter().find_map(|item| match item {
            Item::Storage(s) if s.name == name => Some(s),
            _ => None,
        })
    }

    /// A stream by its path from this storage.
    pub fn find(&self, path: &[&str]) -> Option<&Vec<u8>> {
        match path {
            [] => None,
            [last] => self.stream(last),
            [first, rest @ ..] => self.storage(first)?.find(rest),
        }
    }

    pub fn with_stream(mut self, name: &str, data: Vec<u8>) -> Storage {
        self.children.push(Item::Stream(name.to_string(), data));
        self
    }

    pub fn with_storage(mut self, storage: Storage) -> Storage {
        self.children.push(Item::Storage(storage));
        self
    }

    /// Every stream, by path, depth first.
    pub fn streams(&self) -> Vec<(Vec<String>, &Vec<u8>)> {
        let mut out = Vec::new();
        for item in &self.children {
            match item {
                Item::Stream(name, data) => out.push((vec![name.clone()], data)),
                Item::Storage(storage) => {
                    for (mut path, data) in storage.streams() {
                        path.insert(0, storage.name.clone());
                        out.push((path, data));
                    }
                }
            }
        }
        out
    }
}

pub fn is_compound(data: &[u8]) -> bool {
    data.starts_with(&SIGNATURE)
}

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().expect("four bytes"))
}

// --------------------------------------------------------------- reading --

struct Reader<'a> {
    data: &'a [u8],
    shift: u32,
    fat: Vec<u32>,
}

impl Reader<'_> {
    fn sector_size(&self) -> usize {
        1 << self.shift
    }

    fn sector(&self, n: u32) -> Result<&[u8], String> {
        let start = (n as usize + 1).checked_mul(self.sector_size())
            .ok_or("A sector number past the end of the file.")?;
        self.data.get(start..start + self.sector_size())
            .ok_or_else(|| format!("Sector {n} is past the end of the file."))
    }

    /// The sectors of a chain, in order. A chain longer than the FAT is
    /// a loop.
    fn chain(&self, start: u32) -> Result<Vec<u32>, String> {
        let mut out = Vec::new();
        let mut at = start;
        while at != ENDOFCHAIN {
            if out.len() > self.fat.len() {
                return Err("A sector chain loops.".to_string());
            }
            out.push(at);
            at = *self.fat.get(at as usize)
                .ok_or_else(|| format!("Sector {at} is not in the FAT."))?;
            if at == FREESECT || at == FATSECT || at == DIFSECT {
                return Err(format!("A chain runs into a sector marked {at:#x}."));
            }
        }
        Ok(out)
    }

    fn read_chain(&self, start: u32) -> Result<Vec<u8>, String> {
        let sectors = self.chain(start)?;
        let mut out = Vec::with_capacity(sectors.len() << self.shift);
        for n in sectors {
            out.extend_from_slice(self.sector(n)?);
        }
        Ok(out)
    }
}

struct RawEntry {
    name: String,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    clsid: [u8; 16],
    start: u32,
    size: u64,
}

/// Read a compound file into its tree of storages and streams.
pub fn read(data: &[u8]) -> Result<Storage, String> {
    if data.len() < 512 || !is_compound(data) {
        return Err("Not a compound file: no D0 CF 11 E0 signature.".to_string());
    }
    let major = u16_at(data, 0x1a);
    let shift = u32::from(u16_at(data, 0x1e));
    if u16_at(data, 0x1c) != 0xfffe {
        return Err("A compound file that is not little endian.".to_string());
    }
    match (major, shift) {
        (3, 9) | (4, 12) => {}
        _ => return Err(format!("Compound file version {major} with {}-byte sectors.",
                                1u64 << shift.min(63))),
    }
    let mini_shift = u16_at(data, 0x20);
    if mini_shift != 6 {
        return Err(format!("Mini sectors of 2^{mini_shift} bytes."));
    }
    let fat_sectors = u32_at(data, 0x2c) as usize;
    let first_directory = u32_at(data, 0x30);
    // [MS-CFB] 2.2 fixes the cutoff at 4096; a larger one in the field
    // would only size a reservation for a stream that then walks the
    // mini FAT.
    let cutoff = u64::from(u32_at(data, 0x38)).min(4096);
    let first_minifat = u32_at(data, 0x3c);
    let mut difat_next = u32_at(data, 0x44);
    let difat_count = u32_at(data, 0x48) as usize;

    let mut reader = Reader { data, shift, fat: Vec::new() };
    let per_sector = reader.sector_size() / 4;
    // The DIFAT: 109 entries in the header, then a chain of sectors each
    // ending in the next one's number.
    let mut difat: Vec<u32> = (0..HEADER_DIFAT).map(|i| u32_at(data, 0x4c + 4 * i)).collect();
    // The count is the header's claim; the file has only so many
    // sectors, and a chain longer than that has come back on itself.
    let sectors_in_file = data.len() / reader.sector_size();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..difat_count.min(sectors_in_file) {
        if difat_next == ENDOFCHAIN || difat_next == FREESECT {
            break;
        }
        if !seen.insert(difat_next) {
            return Err(format!("The DIFAT chain loops at sector {difat_next}."));
        }
        let sector = reader.sector(difat_next)?;
        difat.extend((0..per_sector - 1).map(|i| u32_at(sector, 4 * i)));
        difat_next = u32_at(sector, 4 * (per_sector - 1));
    }
    if fat_sectors > difat.len() {
        return Err(format!("{fat_sectors} FAT sectors, and the DIFAT lists {}.", difat.len()));
    }
    let mut fat = Vec::with_capacity(fat_sectors * per_sector);
    for &n in &difat[..fat_sectors] {
        let sector = reader.sector(n)?;
        fat.extend((0..per_sector).map(|i| u32_at(sector, 4 * i)));
    }
    reader.fat = fat;

    let directory = reader.read_chain(first_directory)?;
    let mut entries = Vec::new();
    for raw in directory.chunks_exact(128) {
        let name_bytes = (u16_at(raw, 64) as usize).min(64);
        let units: Vec<u16> = raw[..name_bytes].chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
        let size = u64::from_le_bytes(raw[120..128].try_into().expect("eight bytes"));
        entries.push(RawEntry {
            name: String::from_utf16_lossy(&units),
            kind: raw[66],
            left: u32_at(raw, 68),
            right: u32_at(raw, 72),
            child: u32_at(raw, 76),
            clsid: raw[80..96].try_into().expect("sixteen bytes"),
            start: u32_at(raw, 116),
            // Version 3 writers may leave garbage in the high half.
            size: if major == 3 { size & 0xffff_ffff } else { size },
        });
    }
    let root = entries.first().filter(|e| e.kind == 5)
        .ok_or("The first directory entry is not the root.")?;
    let mini_stream = if root.start == ENDOFCHAIN { Vec::new() } else { reader.read_chain(root.start)? };
    let minifat: Vec<u32> = if first_minifat == ENDOFCHAIN || first_minifat == FREESECT {
        Vec::new()
    } else {
        reader.read_chain(first_minifat)?.chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().expect("four bytes"))).collect()
    };

    let stream_data = |entry: &RawEntry| -> Result<Vec<u8>, String> {
        let size = entry.size as usize;
        if entry.size < cutoff {
            let mut out = Vec::with_capacity(size);
            let mut at = entry.start;
            let mut steps = 0;
            while out.len() < size {
                if at == ENDOFCHAIN || steps > minifat.len() {
                    return Err(format!("Stream {:?}: the mini chain ends early.", entry.name));
                }
                let start = at as usize * MINI_SECTOR;
                let piece = mini_stream.get(start..start + MINI_SECTOR)
                    .ok_or_else(|| format!("Stream {:?}: a mini sector past the mini stream.",
                                           entry.name))?;
                out.extend_from_slice(piece);
                at = *minifat.get(at as usize)
                    .ok_or_else(|| format!("Stream {:?}: mini sector {at} is not in the mini \
                                            FAT.", entry.name))?;
                steps += 1;
            }
            out.truncate(size);
            Ok(out)
        } else {
            let mut out = reader.read_chain(entry.start)?;
            if out.len() < size {
                return Err(format!("Stream {:?} is {size} bytes and its chain {}.", entry.name,
                                   out.len()));
            }
            out.truncate(size);
            Ok(out)
        }
    };

    // Walk the tree. Each entry may be visited once; a second visit is
    // a cycle. The siblings are a red-black tree in a well-formed file
    // and may be a chain in another, so the in-order walk keeps its own
    // stack rather than recursing once per entry.
    let mut visited = vec![false; entries.len()];
    fn siblings(entries: &[RawEntry], start: u32, visited: &mut [bool], out: &mut Vec<usize>)
                -> Result<(), String> {
        let mut stack = Vec::new();
        let mut at = start;
        loop {
            while at != NOSTREAM {
                let index = at as usize;
                if index >= entries.len() || visited[index] {
                    return Err("The directory tree has a cycle or a dangling link.".to_string());
                }
                visited[index] = true;
                stack.push(index);
                at = entries[index].left;
            }
            let Some(index) = stack.pop() else { return Ok(()) };
            out.push(index);
            at = entries[index].right;
        }
    }
    fn build(entries: &[RawEntry], index: usize, visited: &mut [bool],
             data: &dyn Fn(&RawEntry) -> Result<Vec<u8>, String>, depth: usize)
             -> Result<Storage, String> {
        if depth > 64 {
            return Err("Storages nested more than 64 deep.".to_string());
        }
        let entry = &entries[index];
        let mut storage = Storage { name: entry.name.clone(), clsid: entry.clsid,
                                    children: Vec::new() };
        let mut order = Vec::new();
        siblings(entries, entry.child, visited, &mut order)?;
        for child in order {
            match entries[child].kind {
                1 => storage.children.push(Item::Storage(build(entries, child, visited, data,
                                                               depth + 1)?)),
                2 => storage.children.push(Item::Stream(entries[child].name.clone(),
                                                        data(&entries[child])?)),
                other => return Err(format!("Directory entry {child} has type {other}.")),
            }
        }
        Ok(storage)
    }
    visited[0] = true;
    build(&entries, 0, &mut visited, &stream_data, 0)
}

// --------------------------------------------------------------- writing --

/// The order a storage's children are kept in: shorter names first,
/// then by upper-cased UTF-16 code unit.
fn compare(a: &str, b: &str) -> std::cmp::Ordering {
    let upper = |s: &str| -> Vec<u16> {
        s.encode_utf16().map(|u| match char::from_u32(u32::from(u)) {
            Some(c) => {
                let mut up = c.to_uppercase();
                match (up.next(), up.next()) {
                    (Some(single), None) if (single as u32) <= 0xffff => single as u32 as u16,
                    _ => u,
                }
            }
            None => u,
        }).collect()
    };
    let (ua, ub) = (upper(a), upper(b));
    ua.len().cmp(&ub.len()).then(ua.cmp(&ub))
}

struct Flat {
    name: String,
    kind: u8,
    clsid: [u8; 16],
    left: u32,
    right: u32,
    child: u32,
    red: bool,
    start: u32,
    size: u64,
    data: Option<usize>,
}

/// Lay a storage's children out as a balanced tree of directory
/// entries: the middle one at the root, recursively. Every null link is
/// then at one of two depths, and colouring the nodes just above the
/// deeper one red - they are all leaves - makes it a valid red-black
/// tree with the same number of black nodes on every path.
fn balance(indices: &[u32], flat: &mut [Flat]) -> u32 {
    fn place(indices: &[u32], flat: &mut [Flat], depth: usize, depths: &mut Vec<(u32, usize)>,
             nulls: &mut (usize, usize)) -> u32 {
        if indices.is_empty() {
            nulls.0 = nulls.0.min(depth);
            nulls.1 = nulls.1.max(depth);
            return NOSTREAM;
        }
        let mid = indices.len() / 2;
        let node = indices[mid];
        depths.push((node, depth));
        let left = place(&indices[..mid], flat, depth + 1, depths, nulls);
        let right = place(&indices[mid + 1..], flat, depth + 1, depths, nulls);
        flat[node as usize].left = left;
        flat[node as usize].right = right;
        node
    }
    let mut depths = Vec::new();
    let mut nulls = (usize::MAX, 0);
    let root = place(indices, flat, 0, &mut depths, &mut nulls);
    if nulls.0 != nulls.1 {
        for (node, depth) in depths {
            flat[node as usize].red = depth + 1 == nulls.1;
        }
    }
    root
}

fn flatten<'a>(storage: &'a Storage, kind: u8, flat: &mut Vec<Flat>, data: &mut Vec<&'a [u8]>)
               -> usize {
    let index = flat.len();
    flat.push(Flat { name: storage.name.clone(), kind, clsid: storage.clsid, left: NOSTREAM,
                     right: NOSTREAM, child: NOSTREAM, red: false, start: 0, size: 0,
                     data: None });
    let mut order: Vec<&Item> = storage.children.iter().collect();
    order.sort_by(|a, b| compare(a.name(), b.name()));
    let mut children = Vec::new();
    for item in order {
        let child = match item {
            Item::Storage(s) => flatten(s, 1, flat, data),
            Item::Stream(name, bytes) => {
                flat.push(Flat { name: name.clone(), kind: 2, clsid: [0; 16], left: NOSTREAM,
                                 right: NOSTREAM, child: NOSTREAM, red: false, start: 0,
                                 size: bytes.len() as u64, data: Some(data.len()) });
                data.push(bytes);
                flat.len() - 1
            }
        };
        children.push(child as u32);
    }
    flat[index].child = balance(&children, flat);
    index
}

/// Write a compound file, version 3, with `root` as its root storage.
pub fn write(root: &Storage) -> Result<Vec<u8>, String> {
    const SECTOR: usize = 512;
    const PER_SECTOR: usize = SECTOR / 4;
    let mut flat = Vec::new();
    let mut data: Vec<&[u8]> = Vec::new();
    flatten(root, 5, &mut flat, &mut data);
    flat[0].name = "Root Entry".to_string();
    for entry in &flat {
        if entry.name.encode_utf16().count() > 31 {
            return Err(format!("The name {:?} is longer than 31 characters.", entry.name));
        }
    }

    // The mini stream: every stream under the cutoff, each starting on a
    // 64-byte boundary.
    let mut mini_stream = Vec::new();
    let mut minifat: Vec<u32> = Vec::new();
    for entry in flat.iter_mut() {
        let Some(i) = entry.data else { continue };
        let bytes = data[i];
        if (bytes.len() as u64) >= MINI_CUTOFF {
            continue;
        }
        if bytes.is_empty() {
            entry.start = ENDOFCHAIN;
            continue;
        }
        let first = minifat.len() as u32;
        let count = bytes.len().div_ceil(MINI_SECTOR);
        for k in 0..count {
            minifat.push(if k + 1 == count { ENDOFCHAIN } else { first + k as u32 + 1 });
        }
        entry.start = first;
        mini_stream.extend_from_slice(bytes);
        mini_stream.resize(minifat.len() * MINI_SECTOR, 0);
    }

    let sectors_for = |bytes: usize| bytes.div_ceil(SECTOR);
    let directory_sectors = sectors_for(flat.len() * 128);
    let minifat_sectors = sectors_for(minifat.len() * 4);
    let mini_stream_sectors = sectors_for(mini_stream.len());
    let big: Vec<usize> = flat.iter().enumerate()
        .filter(|(_, e)| e.data.is_some() && e.size >= MINI_CUTOFF).map(|(i, _)| i).collect();
    let big_sectors: usize = big.iter().map(|&i| sectors_for(flat[i].size as usize)).sum();
    let content = directory_sectors + minifat_sectors + mini_stream_sectors + big_sectors;

    // The FAT has to cover itself and the DIFAT sectors too.
    let (mut fat_sectors, mut difat_sectors) = (0usize, 0usize);
    loop {
        let total = content + fat_sectors + difat_sectors;
        let needed = total.div_ceil(PER_SECTOR);
        let difat_needed = needed.saturating_sub(HEADER_DIFAT).div_ceil(PER_SECTOR - 1);
        if needed == fat_sectors && difat_needed == difat_sectors {
            break;
        }
        fat_sectors = needed;
        difat_sectors = difat_needed;
    }

    // Layout: FAT, DIFAT, directory, mini FAT, mini stream, big streams.
    let total = content + fat_sectors + difat_sectors;
    let mut fat = vec![FREESECT; fat_sectors * PER_SECTOR];
    let fat_start = 0;
    let difat_start = fat_sectors;
    fat[..fat_sectors].fill(FATSECT);
    fat[difat_start..difat_start + difat_sectors].fill(DIFSECT);
    let mut next = fat_sectors + difat_sectors;
    let mut run = |fat: &mut Vec<u32>, count: usize| -> u32 {
        if count == 0 {
            return ENDOFCHAIN;
        }
        let first = next;
        for k in 0..count {
            fat[first + k] = if k + 1 == count { ENDOFCHAIN } else { (first + k + 1) as u32 };
        }
        next += count;
        first as u32
    };
    let directory_start = run(&mut fat, directory_sectors);
    let minifat_start = run(&mut fat, minifat_sectors);
    let mini_stream_start = run(&mut fat, mini_stream_sectors);
    for &i in &big {
        flat[i].start = run(&mut fat, sectors_for(flat[i].size as usize));
    }
    flat[0].start = mini_stream_start;
    flat[0].size = mini_stream.len() as u64;

    let mut out = vec![0u8; SECTOR * (total + 1)];
    // The header.
    out[..8].copy_from_slice(&SIGNATURE);
    out[0x18..0x1a].copy_from_slice(&0x3eu16.to_le_bytes());
    out[0x1a..0x1c].copy_from_slice(&3u16.to_le_bytes());
    out[0x1c..0x1e].copy_from_slice(&0xfffeu16.to_le_bytes());
    out[0x1e..0x20].copy_from_slice(&9u16.to_le_bytes());
    out[0x20..0x22].copy_from_slice(&6u16.to_le_bytes());
    out[0x2c..0x30].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
    out[0x30..0x34].copy_from_slice(&directory_start.to_le_bytes());
    out[0x38..0x3c].copy_from_slice(&(MINI_CUTOFF as u32).to_le_bytes());
    out[0x3c..0x40].copy_from_slice(&minifat_start.to_le_bytes());
    out[0x40..0x44].copy_from_slice(&(minifat_sectors as u32).to_le_bytes());
    let first_difat = if difat_sectors == 0 { ENDOFCHAIN } else { difat_start as u32 };
    out[0x44..0x48].copy_from_slice(&first_difat.to_le_bytes());
    out[0x48..0x4c].copy_from_slice(&(difat_sectors as u32).to_le_bytes());
    let fat_list: Vec<u32> = (0..fat_sectors).map(|k| (fat_start + k) as u32).collect();
    for i in 0..HEADER_DIFAT {
        let value = fat_list.get(i).copied().unwrap_or(FREESECT);
        out[0x4c + 4 * i..0x50 + 4 * i].copy_from_slice(&value.to_le_bytes());
    }
    let at = |sector: usize| SECTOR * (sector + 1);
    // DIFAT sectors: 127 entries and a link each.
    let rest = fat_list.get(HEADER_DIFAT..).unwrap_or(&[]);
    for k in 0..difat_sectors {
        let base = at(difat_start + k);
        for j in 0..PER_SECTOR - 1 {
            let value = rest.get(k * (PER_SECTOR - 1) + j).copied().unwrap_or(FREESECT);
            out[base + 4 * j..base + 4 * j + 4].copy_from_slice(&value.to_le_bytes());
        }
        let link = if k + 1 == difat_sectors { ENDOFCHAIN } else { (difat_start + k + 1) as u32 };
        out[base + SECTOR - 4..base + SECTOR].copy_from_slice(&link.to_le_bytes());
    }
    for (k, value) in fat.iter().enumerate() {
        let base = at(fat_start) + 4 * k;
        out[base..base + 4].copy_from_slice(&value.to_le_bytes());
    }
    // The directory, padded with empty entries.
    let directory_base = at(directory_start as usize);
    for slot in 0..directory_sectors * SECTOR / 128 {
        let raw = &mut out[directory_base + 128 * slot..directory_base + 128 * (slot + 1)];
        match flat.get(slot) {
            None => {
                raw[68..80].copy_from_slice(&[0xff; 12]);
            }
            Some(entry) => {
                let units: Vec<u16> = entry.name.encode_utf16().collect();
                for (k, unit) in units.iter().enumerate() {
                    raw[2 * k..2 * k + 2].copy_from_slice(&unit.to_le_bytes());
                }
                raw[64..66].copy_from_slice(&(((units.len() + 1) * 2) as u16).to_le_bytes());
                raw[66] = entry.kind;
                raw[67] = if entry.red { 0 } else { 1 };
                raw[68..72].copy_from_slice(&entry.left.to_le_bytes());
                raw[72..76].copy_from_slice(&entry.right.to_le_bytes());
                raw[76..80].copy_from_slice(&entry.child.to_le_bytes());
                raw[80..96].copy_from_slice(&entry.clsid);
                raw[116..120].copy_from_slice(&entry.start.to_le_bytes());
                raw[120..128].copy_from_slice(&entry.size.to_le_bytes());
            }
        }
    }
    if minifat_sectors > 0 {
        let base = at(minifat_start as usize);
        let mut padded = minifat.clone();
        padded.resize(minifat_sectors * PER_SECTOR, FREESECT);
        for (k, value) in padded.iter().enumerate() {
            out[base + 4 * k..base + 4 * k + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    if mini_stream_sectors > 0 {
        let base = at(mini_stream_start as usize);
        out[base..base + mini_stream.len()].copy_from_slice(&mini_stream);
    }
    for &i in &big {
        let base = at(flat[i].start as usize);
        let bytes = data[flat[i].data.expect("a stream")];
        out[base..base + bytes.len()].copy_from_slice(bytes);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(sizes: &[usize]) -> Storage {
        let mut inner = Storage::new("Inner");
        for (i, &size) in sizes.iter().enumerate() {
            let data: Vec<u8> = (0..size).map(|k| (k * 7 + i) as u8).collect();
            inner = inner.with_stream(&format!("s{i}"), data);
        }
        Storage::new("Root Entry")
            .with_stream("Zed", vec![1, 2, 3])
            .with_stream("a", Vec::new())
            .with_stream("Big", vec![9; 5000])
            .with_storage(inner)
    }

    fn sorted(mut storage: Storage) -> Storage {
        storage.children.sort_by(|a, b| compare(a.name(), b.name()));
        for item in storage.children.iter_mut() {
            if let Item::Storage(s) = item {
                *s = sorted(std::mem::take(s));
            }
        }
        storage
    }

    /// What is written reads back, in the directory's order, for streams
    /// either side of the mini-stream cutoff and of every sector edge.
    #[test]
    fn test_what_is_written_reads_back() {
        let sizes = [0, 1, 63, 64, 65, 511, 512, 513, 4095, 4096, 4097, 70_000];
        let tree = sample(&sizes);
        let bytes = write(&tree).unwrap();
        assert_eq!(bytes.len() % 512, 0);
        assert_eq!(read(&bytes).unwrap(), sorted(tree));
    }

    /// More than 109 FAT sectors - about 7 MB - needs DIFAT sectors,
    /// and more than 236 needs two, which is the only way to see each
    /// one's last entry read as the link rather than as a FAT sector.
    #[test]
    fn test_a_file_past_the_header_difat_reads_back() {
        let data: Vec<u8> = (0..16u32 << 20).map(|i| (i % 251) as u8).collect();
        let tree = Storage::new("Root Entry").with_stream("Large", data);
        let bytes = write(&tree).unwrap();
        assert_eq!(u32_at(&bytes, 0x48), 2, "DIFAT sectors");
        assert_eq!(read(&bytes).unwrap(), tree);
    }

    /// A stream of fewer than 4096 bytes goes in the mini stream and one
    /// of 4096 does not: readers decide where to look by the size alone.
    #[test]
    fn test_the_mini_stream_cutoff() {
        let mini_size = |length: usize| {
            let bytes = write(&Storage::new("Root Entry").with_stream("S", vec![1; length]))
                .unwrap();
            // The root entry is the directory's first; its size is the
            // mini stream's.
            let directory = 512 * (u32_at(&bytes, 0x30) as usize + 1);
            u64::from_le_bytes(bytes[directory + 120..directory + 128].try_into().unwrap())
        };
        assert_eq!(mini_size(4095), 4096);
        assert_eq!(mini_size(4096), 0);
        assert_eq!(mini_size(1), 64);
    }

    /// Version 3 writers may leave the high half of a stream's size
    /// unset; it is ignored, as the specification says.
    #[test]
    fn test_a_version_3_size_ignores_its_high_half() {
        let tree = Storage::new("Root Entry").with_stream("S", vec![7; 100]);
        let mut bytes = write(&tree).unwrap();
        let directory = 512 * (u32_at(&bytes, 0x30) as usize + 1);
        bytes[directory + 128 + 124] = 0xff;
        assert_eq!(read(&bytes).unwrap(), tree);
    }

    /// The colours written into the directory make each storage's
    /// children a red-black tree, read back from the bytes.
    #[test]
    fn test_the_written_directory_is_red_black() {
        let mut root = Storage::new("Root Entry");
        for i in 0..21 {
            root = root.with_stream(&format!("stream {i:02}"), vec![i as u8]);
        }
        let bytes = write(&root).unwrap();
        let directory = 512 * (u32_at(&bytes, 0x30) as usize + 1);
        let entry = |n: u32| &bytes[directory + 128 * n as usize..directory + 128 * (n as usize + 1)];
        fn check<'a>(entry: &dyn Fn(u32) -> &'a [u8], at: u32, parent_red: bool) -> usize {
            if at == NOSTREAM {
                return 1;
            }
            let raw = entry(at);
            let red = raw[67] == 0;
            assert!(!(parent_red && red), "a red node with a red child");
            let (l, r) = (check(entry, u32_at(raw, 68), red), check(entry, u32_at(raw, 72), red));
            assert_eq!(l, r, "unequal black heights");
            l + usize::from(!red)
        }
        let top = u32_at(entry(0), 76);
        assert_eq!(entry(top)[67], 1, "the root is black");
        assert!((1..=21).any(|n| entry(n)[67] == 0), "21 nodes and no red one");
        check(&entry, top, false);
    }

    /// Names are ordered by length first - "Zed" before "Inner" - and
    /// then without regard to case.
    #[test]
    fn test_the_directory_order() {
        let mut names = vec!["Inner", "Zed", "a", "Big", "\u{6}DataSpaces", "aB", "Ab"];
        names.sort_by(|a, b| compare(a, b));
        assert_eq!(names, ["a", "aB", "Ab", "Big", "Zed", "Inner", "\u{6}DataSpaces"]);
    }

    /// Every path from a storage's tree root to a null link passes the
    /// same number of black nodes, and no red node has a red child.
    #[test]
    fn test_the_sibling_trees_are_red_black() {
        for n in 1..40u32 {
            let mut flat: Vec<Flat> = (0..n).map(|i| Flat {
                name: i.to_string(), kind: 2, clsid: [0; 16], left: 0, right: 0, child: 0,
                red: false, start: 0, size: 0, data: None }).collect();
            let indices: Vec<u32> = (0..n).collect();
            let root = balance(&indices, &mut flat);
            fn black_height(flat: &[Flat], at: u32, parent_red: bool) -> usize {
                if at == NOSTREAM {
                    return 1;
                }
                let node = &flat[at as usize];
                assert!(!(parent_red && node.red), "a red node with a red child");
                let (l, r) = (black_height(flat, node.left, node.red),
                              black_height(flat, node.right, node.red));
                assert_eq!(l, r, "unequal black heights");
                l + usize::from(!node.red)
            }
            assert!(!flat[root as usize].red);
            black_height(&flat, root, false);
            // And it is a search tree, in order.
            fn in_order(flat: &[Flat], at: u32, out: &mut Vec<u32>) {
                if at != NOSTREAM {
                    in_order(flat, flat[at as usize].left, out);
                    out.push(at);
                    in_order(flat, flat[at as usize].right, out);
                }
            }
            let mut order = Vec::new();
            in_order(&flat, root, &mut order);
            assert_eq!(order, indices);
        }
    }

    /// The DIFAT chain was followed as many times as the header's count
    /// said, with nothing against a sector that names itself as the
    /// next: with the count at its maximum that was four billion
    /// rounds of 127 entries each. The FAT chains and the directory
    /// walk were bounded; the files the fixtures came from all have a
    /// DIFAT that ends, so no test followed one that did not.
    #[test]
    fn test_a_loop_in_the_difat_chain_is_an_error() {
        let tree = Storage::new("Root Entry").with_stream("S", vec![1; 100]);
        let mut bytes = write(&tree).unwrap();
        assert_eq!(read(&bytes).unwrap(), tree);
        // One more sector, whose last entry is its own number.
        let own = (bytes.len() / 512 - 1) as u32;
        bytes.extend_from_slice(&[0xff; 508]);
        bytes.extend_from_slice(&own.to_le_bytes());
        bytes[0x44..0x48].copy_from_slice(&own.to_le_bytes());
        bytes[0x48..0x4c].copy_from_slice(&u32::MAX.to_le_bytes());
        let error = read(&bytes).unwrap_err();
        assert!(error.contains("DIFAT chain loops"), "{error}");
        // A count larger than the file, over a chain that does end, is
        // only a count.
        let end = bytes.len() - 4;
        bytes[end..].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        assert_eq!(read(&bytes).unwrap(), tree);
    }

    /// The sibling walk recursed along `left` and `right`, so a
    /// directory whose entries chain through `left` cost one frame per
    /// entry and a long enough chain ran out of stack. The writer
    /// balances its trees and so do real producers, so no fixture had a
    /// chain. The walk is run on a small stack to make the limit sharp.
    #[test]
    fn test_a_directory_chained_through_left_links_is_read() {
        let n = 20_000u32;
        let mut tree = Storage::new("Root Entry");
        for i in 0..n {
            tree = tree.with_stream(&format!("s{i:05}"), Vec::new());
        }
        let mut bytes = write(&tree).unwrap();
        // The writer lays the directory out in one run: entry 0 is the
        // root and 1..=n the streams, in the directory's order. Chain
        // them: root -> 1, each -> the next through `left`.
        let directory = 512 * (u32_at(&bytes, 0x30) as usize + 1);
        let link = |bytes: &mut [u8], entry: u32, field: usize, to: u32| {
            let at = directory + 128 * entry as usize + field;
            bytes[at..at + 4].copy_from_slice(&to.to_le_bytes());
        };
        link(&mut bytes, 0, 76, 1);
        for i in 1..=n {
            link(&mut bytes, i, 68, if i < n { i + 1 } else { NOSTREAM });
            link(&mut bytes, i, 72, NOSTREAM);
        }
        let read_back = std::thread::Builder::new().stack_size(256 * 1024)
            .spawn(move || read(&bytes).map(|s| s.children.len())).unwrap().join().unwrap();
        assert_eq!(read_back.unwrap(), n as usize);
    }

    #[test]
    fn test_a_loop_in_a_chain_is_an_error() {
        let tree = Storage::new("Root Entry").with_stream("Big", vec![1; 5000]);
        let mut bytes = write(&tree).unwrap();
        // The FAT is sector 0; point the big stream's last sector at its
        // first.
        let fat = 512;
        let entries: Vec<u32> = (0..128).map(|i| u32_at(&bytes, fat + 4 * i)).collect();
        let last = entries.iter().rposition(|&v| v == ENDOFCHAIN).unwrap();
        let first = (last - 9) as u32;
        bytes[fat + 4 * last..fat + 4 * last + 4].copy_from_slice(&first.to_le_bytes());
        assert!(read(&bytes).unwrap_err().contains("loops"));
    }
}
