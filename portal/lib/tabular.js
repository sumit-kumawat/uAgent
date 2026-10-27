"use strict";

// Reads a system inventory from a CSV file or an .xlsx workbook into rows of named cells. No third-party
// parser is used: CSV is parsed directly and .xlsx is read through the ZIP utility and its XML sheets.
const { readEntries } = require("./zipFile");

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  const content = text.replace(/^\ufeff/, "");
  for (let i = 0; i < content.length; i += 1) {
    const ch = content[i];
    if (inQuotes) {
      if (ch === '"') {
        if (content[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\r") {
      // Handled with the following \n.
    } else if (ch === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += ch;
    }
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function columnToIndex(ref) {
  let index = 0;
  for (const ch of ref.replace(/\d+/g, "")) {
    index = index * 26 + (ch.charCodeAt(0) - 64);
  }
  return index - 1;
}

function decodeXml(value) {
  return value
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&amp;/g, "&");
}

function parseSharedStrings(xml) {
  if (!xml) {
    return [];
  }
  const text = xml.toString("utf8");
  const strings = [];
  const siRegex = /<si>([\s\S]*?)<\/si>/g;
  let match;
  while ((match = siRegex.exec(text))) {
    const parts = [...match[1].matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map((m) => decodeXml(m[1]));
    strings.push(parts.join(""));
  }
  return strings;
}

function firstSheetName(entries) {
  for (const key of entries.keys()) {
    const sheet = /^xl\/worksheets\/(sheet\d+\.xml)$/.exec(key);
    if (sheet) {
      return key;
    }
  }
  return null;
}

function parseXlsx(buffer) {
  const entries = readEntries(buffer);
  const shared = parseSharedStrings(entries.get("xl/sharedStrings.xml"));
  const sheetKey = firstSheetName(entries);
  if (!sheetKey) {
    throw new Error("The workbook has no worksheets.");
  }
  const xml = entries.get(sheetKey).toString("utf8");
  const rows = [];
  const rowRegex = /<row[^>]*r="(\d+)"[^>]*>([\s\S]*?)<\/row>/g;
  let rowMatch;
  while ((rowMatch = rowRegex.exec(xml))) {
    const cells = [];
    const cellRegex = /<c[^>]*r="([A-Z]+)\d+"([^>]*)>([\s\S]*?)<\/c>/g;
    let cellMatch;
    while ((cellMatch = cellRegex.exec(rowMatch[2]))) {
      const index = columnToIndex(cellMatch[1]);
      const attrs = cellMatch[2];
      const body = cellMatch[3];
      const typeMatch = /t="([^"]+)"/.exec(attrs);
      const type = typeMatch ? typeMatch[1] : "";
      let value = "";
      if (type === "inlineStr") {
        value = [...body.matchAll(/<t[^>]*>([\s\S]*?)<\/t>/g)].map((m) => decodeXml(m[1])).join("");
      } else {
        const v = /<v>([\s\S]*?)<\/v>/.exec(body);
        const raw = v ? decodeXml(v[1]) : "";
        value = type === "s" ? shared[Number(raw)] || "" : raw;
      }
      cells[index] = value;
    }
    for (let i = 0; i < cells.length; i += 1) {
      if (cells[i] === undefined) {
        cells[i] = "";
      }
    }
    rows.push(cells);
  }
  return rows;
}

// Returns { headers, records } where records are objects keyed by a normalized header name.
function readTable(buffer, fileName) {
  const isXlsx = /\.xlsx$/i.test(fileName) || (buffer.length > 4 && buffer[0] === 0x50 && buffer[1] === 0x4b);
  const rows = isXlsx ? parseXlsx(buffer) : parseCsv(buffer.toString("utf8"));
  const nonEmpty = rows.filter((r) => r.some((cell) => String(cell).trim() !== ""));
  if (nonEmpty.length === 0) {
    return { headers: [], records: [] };
  }
  const headers = nonEmpty[0].map((h) => String(h).trim());
  const keys = headers.map((h) => h.toLowerCase().replace(/[\s_-]+/g, ""));
  const records = [];
  for (let r = 1; r < nonEmpty.length; r += 1) {
    const row = nonEmpty[r];
    const record = {};
    keys.forEach((key, i) => {
      if (key) {
        record[key] = String(row[i] === undefined ? "" : row[i]).trim();
      }
    });
    record.__row = r + 1;
    records.push(record);
  }
  return { headers, records };
}

module.exports = { readTable, parseCsv };
