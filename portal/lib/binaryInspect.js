"use strict";

// Reads installer metadata without executing anything: Windows PE version resources and Authenticode
// presence for EXE files, and the Compound File summary and Property table for MSI files. Files are
// read in small pieces, so multi-gigabyte installers never load into memory.
const fs = require("fs");

const MZ = 0x5a4d;
const PE_SIGNATURE = 0x00004550;
const CFB_SIGNATURE = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
const RT_VERSION = 16;
const MAX_STREAM_BYTES = 32 * 1024 * 1024;

class FileReader {
  constructor(file) {
    this.fd = fs.openSync(file, "r");
    this.size = fs.fstatSync(this.fd).size;
  }

  read(offset, length) {
    if (offset < 0 || length < 0 || offset + length > this.size) {
      throw new Error("The file is truncated or malformed.");
    }
    const buffer = Buffer.alloc(length);
    let done = 0;
    while (done < length) {
      const n = fs.readSync(this.fd, buffer, done, length - done, offset + done);
      if (n <= 0) {
        throw new Error("The file is truncated or malformed.");
      }
      done += n;
    }
    return buffer;
  }

  close() {
    fs.closeSync(this.fd);
  }
}

function detectType(file) {
  const reader = new FileReader(file);
  try {
    if (reader.size < 512) {
      return null;
    }
    const head = reader.read(0, 8);
    if (head.equals(CFB_SIGNATURE)) {
      return "msi";
    }
    if (head.readUInt16LE(0) === MZ) {
      return "exe";
    }
    return null;
  } finally {
    reader.close();
  }
}

// --- PE ------------------------------------------------------------------------------------------

const MACHINES = { 0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64" };

function inspectPe(file) {
  const reader = new FileReader(file);
  try {
    const dos = reader.read(0, 64);
    if (dos.readUInt16LE(0) !== MZ) {
      throw new Error("The file is not a Windows executable.");
    }
    const peOffset = dos.readUInt32LE(0x3c);
    const coff = reader.read(peOffset, 24);
    if (coff.readUInt32LE(0) !== PE_SIGNATURE) {
      throw new Error("The file is not a Windows executable.");
    }
    const machine = coff.readUInt16LE(4);
    const sectionCount = coff.readUInt16LE(6);
    const optionalSize = coff.readUInt16LE(20);
    const optional = reader.read(peOffset + 24, optionalSize);
    const pe32Plus = optional.readUInt16LE(0) === 0x20b;
    const dirBase = pe32Plus ? 112 : 96;
    const dirCount = optional.readUInt32LE(dirBase - 4);
    const directory = (index) => (index < dirCount
      ? { rva: optional.readUInt32LE(dirBase + index * 8), size: optional.readUInt32LE(dirBase + index * 8 + 4) }
      : { rva: 0, size: 0 });

    const sectionTable = reader.read(peOffset + 24 + optionalSize, sectionCount * 40);
    const sections = [];
    for (let i = 0; i < sectionCount; i += 1) {
      const base = i * 40;
      sections.push({
        virtualSize: sectionTable.readUInt32LE(base + 8),
        virtualAddress: sectionTable.readUInt32LE(base + 12),
        rawSize: sectionTable.readUInt32LE(base + 16),
        rawOffset: sectionTable.readUInt32LE(base + 20)
      });
    }
    const toOffset = (rva) => {
      const section = sections.find((s) => rva >= s.virtualAddress && rva < s.virtualAddress + Math.max(s.virtualSize, s.rawSize));
      return section ? section.rawOffset + (rva - section.virtualAddress) : -1;
    };

    // The security directory holds a file offset, not an RVA.
    const security = directory(4);
    const hasSignature = security.rva > 0 && security.size > 8 && security.rva + security.size <= reader.size;

    let version = {};
    const resources = directory(2);
    if (resources.rva && resources.size) {
      const resourceBase = toOffset(resources.rva);
      if (resourceBase > 0) {
        version = readVersionResource(reader, resourceBase, toOffset) || {};
      }
    }
    return { architecture: MACHINES[machine] || "unknown", hasSignature, ...version };
  } finally {
    reader.close();
  }
}

function readResourceDirectory(reader, base, offset) {
  const header = reader.read(base + offset, 16);
  const count = header.readUInt16LE(12) + header.readUInt16LE(14);
  const entries = reader.read(base + offset + 16, count * 8);
  const list = [];
  for (let i = 0; i < count; i += 1) {
    const id = entries.readUInt32LE(i * 8);
    const target = entries.readUInt32LE(i * 8 + 4);
    list.push({ named: Boolean(id & 0x80000000), id: id & 0x7fffffff, directory: Boolean(target & 0x80000000), offset: target & 0x7fffffff });
  }
  return list;
}

function readVersionResource(reader, base, toOffset) {
  const versionType = readResourceDirectory(reader, base, 0).find((e) => !e.named && e.id === RT_VERSION && e.directory);
  if (!versionType) {
    return null;
  }
  const name = readResourceDirectory(reader, base, versionType.offset).find((e) => e.directory);
  if (!name) {
    return null;
  }
  const language = readResourceDirectory(reader, base, name.offset).find((e) => !e.directory);
  if (!language) {
    return null;
  }
  const entry = reader.read(base + language.offset, 16);
  const dataOffset = toOffset(entry.readUInt32LE(0));
  const dataSize = entry.readUInt32LE(4);
  if (dataOffset < 0 || dataSize < 64 || dataSize > 1024 * 1024) {
    return null;
  }
  return parseVersionInfo(reader.read(dataOffset, dataSize));
}

function parseVersionInfo(buffer) {
  const align = (p) => (p + 3) & ~3;
  function block(offset) {
    const length = buffer.readUInt16LE(offset);
    const valueLength = buffer.readUInt16LE(offset + 2);
    const type = buffer.readUInt16LE(offset + 4);
    let p = offset + 6;
    let key = "";
    while (p + 1 < buffer.length) {
      const c = buffer.readUInt16LE(p);
      p += 2;
      if (c === 0) {
        break;
      }
      key += String.fromCharCode(c);
    }
    const valueStart = align(p);
    const valueBytes = type === 1 ? valueLength * 2 : valueLength;
    const end = Math.min(offset + length, buffer.length);
    return { key, type, valueStart, valueBytes, childrenStart: align(valueStart + valueBytes), end };
  }
  function children(parent) {
    const list = [];
    let p = parent.childrenStart;
    while (p + 6 < parent.end) {
      const child = block(p);
      if (child.end <= p) {
        break;
      }
      list.push(child);
      p = align(child.end);
    }
    return list;
  }

  const root = block(0);
  if (root.key !== "VS_VERSION_INFO") {
    return null;
  }
  const result = {};
  if (root.valueBytes >= 52 && buffer.readUInt32LE(root.valueStart) === 0xfeef04bd) {
    const v = root.valueStart;
    const quad = (ms, ls) => `${buffer.readUInt32LE(ms) >>> 16}.${buffer.readUInt32LE(ms) & 0xffff}.${buffer.readUInt32LE(ls) >>> 16}.${buffer.readUInt32LE(ls) & 0xffff}`;
    result.fixedFileVersion = quad(v + 8, v + 12);
    result.fixedProductVersion = quad(v + 16, v + 20);
  }
  const strings = {};
  for (const section of children(root)) {
    if (section.key !== "StringFileInfo") {
      continue;
    }
    for (const table of children(section)) {
      for (const entry of children(table)) {
        if (entry.valueBytes > 0) {
          const raw = buffer.toString("utf16le", entry.valueStart, Math.min(entry.valueStart + entry.valueBytes, entry.end));
          strings[entry.key] = raw.replace(/\0+$/, "").trim();
        }
      }
    }
  }
  result.productName = strings.ProductName || "";
  result.productVersion = strings.ProductVersion || result.fixedProductVersion || "";
  result.fileVersion = strings.FileVersion || result.fixedFileVersion || "";
  result.companyName = strings.CompanyName || "";
  result.fileDescription = strings.FileDescription || "";
  return result;
}

// --- MSI (Compound File Binary) --------------------------------------------------------------------

const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;

class CompoundFile {
  constructor(reader) {
    this.reader = reader;
    const header = reader.read(0, 512);
    if (!header.subarray(0, 8).equals(CFB_SIGNATURE)) {
      throw new Error("The file is not a Windows Installer package.");
    }
    this.sectorSize = 1 << header.readUInt16LE(0x1e);
    this.miniSectorSize = 1 << header.readUInt16LE(0x20);
    this.miniCutoff = header.readUInt32LE(0x38);
    const fatSectors = [];
    for (let i = 0; i < 109; i += 1) {
      const sector = header.readUInt32LE(0x4c + i * 4);
      if (sector !== FREESECT) {
        fatSectors.push(sector);
      }
    }
    let difat = header.readUInt32LE(0x44);
    let guard = 0;
    while (difat !== ENDOFCHAIN && difat !== FREESECT && guard++ < 100000) {
      const data = this.sector(difat);
      const perSector = this.sectorSize / 4 - 1;
      for (let i = 0; i < perSector; i += 1) {
        const sector = data.readUInt32LE(i * 4);
        if (sector !== FREESECT) {
          fatSectors.push(sector);
        }
      }
      difat = data.readUInt32LE(perSector * 4);
    }
    const fat = Buffer.concat(fatSectors.map((s) => this.sector(s)));
    this.fat = (n) => (n * 4 + 4 <= fat.length ? fat.readUInt32LE(n * 4) : ENDOFCHAIN);

    this.entries = this._readDirectory(header.readUInt32LE(0x30));
    const root = this.entries[0];
    this.miniStream = root ? { start: root.start, size: root.size } : null;
    const miniFatStart = header.readUInt32LE(0x3c);
    const miniFatBytes = miniFatStart === ENDOFCHAIN ? Buffer.alloc(0) : this._chain(miniFatStart, Infinity);
    this.miniFat = (n) => (n * 4 + 4 <= miniFatBytes.length ? miniFatBytes.readUInt32LE(n * 4) : ENDOFCHAIN);
  }

  sector(n) {
    return this.reader.read((n + 1) * this.sectorSize, this.sectorSize);
  }

  _chain(start, maxBytes) {
    const parts = [];
    let total = 0;
    let n = start;
    let guard = 0;
    while (n !== ENDOFCHAIN && n !== FREESECT && total < maxBytes && guard++ < 1000000) {
      parts.push(this.sector(n));
      total += this.sectorSize;
      n = this.fat(n);
    }
    return Buffer.concat(parts);
  }

  _readDirectory(start) {
    const data = this._chain(start, 64 * 1024 * 1024);
    const entries = [];
    for (let p = 0; p + 128 <= data.length; p += 128) {
      const nameLength = data.readUInt16LE(p + 0x40);
      const type = data.readUInt8(p + 0x42);
      const name = nameLength >= 2 ? data.toString("utf16le", p, p + Math.min(nameLength - 2, 62)) : "";
      const size = data.readUInt32LE(p + 0x78) + (this.sectorSize > 512 ? data.readUInt32LE(p + 0x7c) * 0x100000000 : 0);
      entries.push({ name, type, start: data.readUInt32LE(p + 0x74), size });
    }
    return entries;
  }

  find(name) {
    return this.entries.find((e) => e.type === 2 && e.name === name) || null;
  }

  readStream(entry) {
    if (entry.size > MAX_STREAM_BYTES) {
      throw new Error("An installer metadata stream is too large to read.");
    }
    if (entry.size < this.miniCutoff && this.miniStream) {
      const parts = [];
      let n = entry.start;
      let total = 0;
      let guard = 0;
      while (n !== ENDOFCHAIN && n !== FREESECT && total < entry.size && guard++ < 1000000) {
        parts.push(this._miniSector(n));
        total += this.miniSectorSize;
        n = this.miniFat(n);
      }
      return Buffer.concat(parts).subarray(0, entry.size);
    }
    return this._chain(entry.start, entry.size).subarray(0, entry.size);
  }

  _miniSector(n) {
    const offset = n * this.miniSectorSize;
    const perSector = this.sectorSize;
    let sector = this.miniStream.start;
    for (let skip = Math.floor(offset / perSector); skip > 0; skip -= 1) {
      sector = this.fat(sector);
    }
    const data = this.sector(sector);
    const within = offset % perSector;
    return data.subarray(within, within + this.miniSectorSize);
  }
}

// MSI compresses stream names into the CJK range; this restores names such as "!_StringPool".
function decodeMsiName(name) {
  const map = (x) => (x < 10 ? String.fromCharCode(48 + x)
    : x < 36 ? String.fromCharCode(55 + x)
      : x < 62 ? String.fromCharCode(61 + x)
        : x === 62 ? "." : "_");
  let out = "";
  for (const ch of name) {
    const c = ch.charCodeAt(0);
    if (c >= 0x3800 && c < 0x4800) {
      out += map((c - 0x3800) & 0x3f) + map(((c - 0x3800) >> 6) & 0x3f);
    } else if (c >= 0x4800 && c < 0x4840) {
      out += map(c - 0x4800);
    } else if (c === 0x4840) {
      out += "!";
    } else {
      out += ch;
    }
  }
  return out;
}

function decodeText(buffer, codepage) {
  return codepage === 65001 ? buffer.toString("utf8") : buffer.toString("latin1");
}

function readSummary(cfb) {
  const entry = cfb.find("\u0005SummaryInformation");
  if (!entry) {
    return {};
  }
  const data = cfb.readStream(entry);
  if (data.length < 48) {
    return {};
  }
  const section = data.readUInt32LE(44);
  const count = data.readUInt32LE(section + 4);
  const props = {};
  let codepage = 1252;
  const offsets = [];
  for (let i = 0; i < count && section + 8 + i * 8 + 8 <= data.length; i += 1) {
    offsets.push([data.readUInt32LE(section + 8 + i * 8), section + data.readUInt32LE(section + 12 + i * 8)]);
  }
  for (const [id, at] of offsets) {
    if (id === 1 && at + 6 <= data.length && data.readUInt32LE(at) === 2) {
      codepage = data.readUInt16LE(at + 4);
    }
  }
  for (const [id, at] of offsets) {
    if (at + 8 > data.length) {
      continue;
    }
    if (data.readUInt32LE(at) === 30) {
      const length = data.readUInt32LE(at + 4);
      if (at + 8 + length <= data.length) {
        props[id] = decodeText(data.subarray(at + 8, at + 8 + length), codepage).replace(/\0+$/, "").trim();
      }
    }
  }
  return { title: props[2] || "", subject: props[3] || "", author: props[4] || "", template: props[7] || "", packageCode: props[9] || "" };
}

function readProperties(cfb) {
  const byName = new Map(cfb.entries.filter((e) => e.type === 2).map((e) => [decodeMsiName(e.name), e]));
  const poolEntry = byName.get("!_StringPool");
  const dataEntry = byName.get("!_StringData");
  const propertyEntry = byName.get("!Property");
  if (!poolEntry || !dataEntry || !propertyEntry) {
    return {};
  }
  const pool = cfb.readStream(poolEntry);
  const stringData = cfb.readStream(dataEntry);
  if (pool.length < 4) {
    return {};
  }
  const codepage = pool.readUInt16LE(0) | ((pool.readUInt16LE(2) & 0x7fff) << 16);
  const refSize = pool.readUInt16LE(2) & 0x8000 ? 3 : 2;
  const strings = [""];
  let offset = 0;
  const words = pool.length / 2;
  let i = 2;
  while (i + 1 < words) {
    const length = pool.readUInt16LE(i * 2);
    const refs = pool.readUInt16LE(i * 2 + 2);
    if (length === 0 && refs === 0) {
      strings.push("");
      i += 2;
      continue;
    }
    let size = length;
    if (length === 0 && i + 3 < words) {
      size = (pool.readUInt16LE(i * 2 + 6) << 16) + pool.readUInt16LE(i * 2 + 4);
      i += 4;
    } else {
      i += 2;
    }
    strings.push(decodeText(stringData.subarray(offset, offset + size), codepage));
    offset += size;
  }

  const table = cfb.readStream(propertyEntry);
  const rows = Math.floor(table.length / (2 * refSize));
  const ref = (p) => (refSize === 2 ? table.readUInt16LE(p) : table.readUIntLE(p, 3));
  const props = {};
  for (let r = 0; r < rows; r += 1) {
    const key = strings[ref(r * refSize)] || "";
    const value = strings[ref(rows * refSize + r * refSize)] || "";
    if (key) {
      props[key] = value;
    }
  }
  return props;
}

function inspectMsi(file) {
  const reader = new FileReader(file);
  try {
    const cfb = new CompoundFile(reader);
    const summary = readSummary(cfb);
    let properties = {};
    try {
      properties = readProperties(cfb);
    } catch (error) {
      properties = {};
    }
    const platform = (summary.template.split(";")[0] || "").toLowerCase();
    return {
      productName: properties.ProductName || summary.subject || "",
      productVersion: properties.ProductVersion || "",
      manufacturer: properties.Manufacturer || summary.author || "",
      productCode: properties.ProductCode || "",
      upgradeCode: properties.UpgradeCode || "",
      architecture: platform === "x64" || platform === "amd64" ? "x64" : platform === "arm64" ? "arm64" : platform ? "x86" : "unknown",
      hasSignature: Boolean(cfb.find("\u0005DigitalSignature")),
      packageCode: summary.packageCode
    };
  } finally {
    reader.close();
  }
}

module.exports = { detectType, inspectPe, inspectMsi, decodeMsiName };
