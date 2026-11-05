"use strict";

// Minimal ZIP reader and writer, enough to read .xlsx workbooks and to build a small deployment kit
// without a third-party dependency. The reader inflates deflated entries; the writer stores entries
// uncompressed, which keeps text kits tiny and verifiable.
const zlib = require("zlib");

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c;
  }
  return table;
})();

function crc32(buffer) {
  let crc = -1;
  for (let i = 0; i < buffer.length; i += 1) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buffer[i]) & 0xff];
  }
  return (crc ^ -1) >>> 0;
}

// maxEntryBytes caps each decompressed entry, so a small archive cannot expand into gigabytes in memory.
function readEntries(buffer, options) {
  const maxEntryBytes = (options && options.maxEntryBytes) || 1024 * 1024 * 1024;
  const entries = new Map();
  let eocd = buffer.length - 22;
  while (eocd >= 0 && buffer.readUInt32LE(eocd) !== 0x06054b50) {
    eocd -= 1;
  }
  if (eocd < 0) {
    throw new Error("The file is not a valid ZIP archive.");
  }
  const count = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);
  for (let i = 0; i < count; i += 1) {
    if (buffer.readUInt32LE(offset) !== 0x02014b50) {
      break;
    }
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString("utf8", offset + 46, offset + 46 + nameLength);
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    const raw = buffer.subarray(dataStart, dataStart + compressedSize);
    if (method === 8) {
      try {
        entries.set(name, zlib.inflateRawSync(raw, { maxOutputLength: maxEntryBytes }));
      } catch (error) {
        if (error.code === "ERR_BUFFER_TOO_LARGE") {
          throw new Error(`${name} in the archive expands to more than ${Math.floor(maxEntryBytes / 1048576)} MB.`);
        }
        throw error;
      }
    } else {
      entries.set(name, Buffer.from(raw));
    }
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

function build(files) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const { name, data } of files) {
    const nameBuffer = Buffer.from(name, "utf8");
    const content = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8");
    const crc = crc32(content);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(content.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(nameBuffer.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, nameBuffer, content);

    const center = Buffer.alloc(46);
    center.writeUInt32LE(0x02014b50, 0);
    center.writeUInt16LE(20, 4);
    center.writeUInt16LE(20, 6);
    center.writeUInt32LE(crc, 16);
    center.writeUInt32LE(content.length, 20);
    center.writeUInt32LE(content.length, 24);
    center.writeUInt16LE(nameBuffer.length, 28);
    center.writeUInt32LE(offset, 42);
    central.push(center, nameBuffer);
    offset += local.length + nameBuffer.length + content.length;
  }
  const centralBuffer = Buffer.concat(central);
  const localBuffer = Buffer.concat(locals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralBuffer.length, 12);
  end.writeUInt32LE(localBuffer.length, 16);
  return Buffer.concat([localBuffer, centralBuffer, end]);
}

module.exports = { readEntries, build, crc32 };
