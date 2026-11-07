import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const P = require('../js/elf.js');
const here = path.dirname(fileURLToPath(import.meta.url));

function fixture(name) {
  return fs.readFileSync(path.join(here, '..', 'samples', name));
}

function assertContiguousAnnotations(model) {
  const a = model.annotations;
  assert.ok(a.length > 0, 'has annotations');
  let pos = 0;
  for (const seg of a) {
    assert.equal(seg.start, pos, `annotation starts at ${pos}`);
    assert.ok(seg.end > seg.start, 'non-empty annotation');
    assert.ok(seg.end <= model.fileSize, 'annotation inside file');
    assert.ok(seg.kind && P.KIND_INFO[seg.kind], `known kind ${seg.kind}`);
    assert.ok(seg.role && P.ROLE_INFO[seg.role], `known role ${seg.role}`);
    pos = seg.end;
  }
  assert.equal(pos, model.fileSize, 'covers entire file');
}

function makeBigEndianElf() {
  // 64-bit BE ELF with 2 section headers and one 4-byte code section.
  const size = 196;
  const buf = Buffer.alloc(size);
  const dv = new DataView(buf.buffer);
  const w16 = (o, v) => dv.setUint16(o, v, false);
  const w32 = (o, v) => dv.setUint32(o, v, false);
  const w64 = (o, v) => dv.setBigUint64(o, BigInt(v), false);

  buf.set([0x7f, 0x45, 0x4c, 0x46], 0);
  buf[4] = 2; // ELF64
  buf[5] = 2; // big endian
  buf[6] = 1;
  buf[7] = 0;
  buf[8] = 0;
  w16(16, 2);   // ET_EXEC
  w16(18, 21);  // EM_PPC64
  w32(20, 1);
  w64(24, 0x1000);
  w64(32, 0);
  w64(40, 64);  // section headers
  w32(48, 0);
  w16(52, 64);
  w16(54, 56);
  w16(56, 0);
  w16(58, 64);
  w16(60, 2);
  w16(62, 0);

  // Section [1] at file offset 128.
  const s = 128;
  w32(s + 0, 0);
  w32(s + 4, 1);        // SHT_PROGBITS
  w64(s + 8, 0x6);      // ALLOC | EXEC
  w64(s + 16, 0x1000);
  w64(s + 24, 192);
  w64(s + 32, 4);
  w32(s + 40, 0);
  w32(s + 44, 0);
  w64(s + 48, 4);
  w64(s + 56, 0);

  buf.set([0x90, 0x90, 0x90, 0x90], 192);
  return buf;
}

test('ELF64 little-endian demo: header, tables, symbols and annotations', () => {
  const m = P.parse(fixture('demo.elf'));
  assert.equal(m.valid, true);
  assert.equal(m.classBits, 64);
  assert.equal(m.littleEndian, true);
  assert.equal(m.header.type, 3);           // ET_DYN
  assert.equal(m.header.machine, 62);       // EM_X86_64
  assert.equal(m.header.entry, 0x23d0);
  assert.equal(m.header.phoff, 64);
  assert.equal(m.header.shoff, 33680);
  assert.equal(m.header.phnum, 13);
  assert.equal(m.header.shnum, 31);
  assert.equal(m.header.shstrndx, 30);
  assert.equal(m.sections.length, 31);
  assert.equal(m.programHeaders.length, 13);

  const text = m.sections.find(s => s.name === '.text');
  assert.ok(text);
  assert.equal(text.offset, 8912);
  assert.equal(text.size, 14974);
  assert.equal(text.kind, 'code');
  assert.equal(m.entrySection.name, '.text');

  assert.equal(m.symbols.length, 53);
  assert.ok(m.symbols.some(s => s.name === '__libc_start_main'));
  assert.equal(m.relocs.length, 66);
  assert.equal(m.dynamic.filter(d => d.tagName === 'DT_NEEDED').length, 1);
  assert.deepEqual(m.needed, ['libc.so.6']);
  assert.equal(m.notes.length, 3);
  const buildId = m.notes.find(n => n.type === 3);
  assert.ok(buildId.descText.includes('C8 91 56 EB'));

  assertContiguousAnnotations(m);
  assert.equal(m.stats.kinds.ehdr, 64);
  assert.equal(m.stats.kinds.phdr, 13 * 56);
  assert.equal(m.stats.kinds.shdr, 31 * 64);
  assert.ok(m.stats.kinds.code > 0);

  const header = Object.fromEntries(m.headerFields.map(f => [f.label, f]));
  assert.match(header.e_type.valueText, /ET_DYN/);
  assert.match(header.e_type.valueText, /共享对象/);
  assert.match(header.EI_OSABI.valueText, /UNIX - System V/);
  for (const f of m.headerFields) assert.doesNotMatch(f.valueText, /undefined/);

  const atMagic = m.annotations.find(s => s.start <= 0 && s.end > 0);
  assert.equal(atMagic.field, 'EI_MAG0-3');
  assert.equal(atMagic.valueText, '7F 45 4C 46');
});

test('ELF64 dynamic executable ls: many sections and relocations', () => {
  const m = P.parse(fixture('ls.elf'));
  assert.equal(m.valid, true);
  assert.equal(m.classBits, 64);
  assert.equal(m.header.type, 3);
  assert.equal(m.header.machine, 62);
  assert.equal(m.header.entry, 0x61d0);
  assert.equal(m.sections.length, 31);
  assert.equal(m.programHeaders.length, 13);
  assert.equal(m.symbols.length, 127);
  assert.equal(m.relocs.length, 329);
  assert.equal(m.dynamic.length, 31);
  assert.equal(m.dynamic.filter(d => d.afterNull).length, 4);
  assert.deepEqual(m.needed, ['libselinux.so.1', 'libc.so.6']);
  assert.equal(m.sections.find(s => s.name === '.text').size, 86174);
  assert.equal(m.entrySection.name, '.text');
  assertContiguousAnnotations(m);
  const buildId = m.notes.find(n => n.type === 3);
  assert.match(buildId.descText, /^15 DF FF 32/);
});

test('ELF32 little-endian demo: 32-bit parsing and REL relocations', () => {
  const m = P.parse(fixture('demo32.elf'));
  assert.equal(m.valid, true);
  assert.equal(m.classBits, 32);
  assert.equal(m.littleEndian, true);
  assert.equal(m.header.type, 3);
  assert.equal(m.header.machine, 3);        // EM_386
  assert.equal(m.header.entry, 0x1410);
  assert.equal(m.header.phoff, 52);
  assert.equal(m.header.shoff, 33464);
  assert.equal(m.header.phnum, 11);
  assert.equal(m.header.shnum, 30);
  assert.equal(m.sections.length, 30);
  assert.equal(m.programHeaders.length, 11);
  assert.equal(m.symbols.length, 54);
  assert.equal(m.relocs.length, 69);
  assert.equal(m.relocs[0].typeName, 'R_386_RELATIVE');
  assert.equal(m.relocs[0].addend, undefined); // SHT_REL has no addend
  assert.deepEqual(m.needed, ['libc.so.6']);

  const text = m.sections.find(s => s.name === '.text');
  assert.equal(text.offset, 4832);
  assert.equal(text.size, 15572);
  assertContiguousAnnotations(m);
  assert.equal(m.stats.kinds.ehdr, 52);
  assert.equal(m.stats.kinds.phdr, 11 * 32);
  assert.equal(m.stats.kinds.shdr, 30 * 40);
});

test('big-endian ELF64 header and section headers', () => {
  const m = P.parse(makeBigEndianElf());
  assert.equal(m.valid, true);
  assert.equal(m.classBits, 64);
  assert.equal(m.littleEndian, false);
  assert.equal(m.header.type, 2);
  assert.equal(m.header.machine, 21);
  assert.equal(m.header.entry, 0x1000);
  assert.equal(m.header.shoff, 64);
  assert.equal(m.sections.length, 2);
  assert.equal(m.sections[1].offset, 192);
  assert.equal(m.sections[1].size, 4);
  assert.equal(m.sections[1].flagsText, 'A X');
  assert.equal(m.sections[1].kind, 'code');

  const entry = m.headerFields.find(f => f.label === 'e_entry');
  assert.match(entry.valueText, /0x0000000000001000/);

  assertContiguousAnnotations(m);
  const code = m.annotations.find(s => s.start === 192);
  assert.equal(code.kind, 'code');
});

test('ET_REL relocatable objects: section-relative symbols and relocations', () => {
  const m = P.parse(fixture('rel-main.o'));
  assert.equal(m.valid, true);
  assert.equal(m.classBits, 64);
  assert.equal(m.header.type, 1);          // ET_REL
  assert.equal(m.header.entry, 0);
  assert.equal(m.programHeaders.length, 0);
  assert.equal(m.sections.length, 14);
  assert.equal(m.symbols.length, 8);
  assert.equal(m.relocs.length, 5);
  const text = m.sections.find(s => s.name === '.text');
  assert.deepEqual([text.offset, text.size], [64, 68]);
  const main = m.symbols.find(s => s.name === 'main');
  assert.equal(main.fileOffset, 64);
  assert.equal(main.value, 0);
  assert.equal(m.relocs[0].typeName, 'R_X86_64_PC32');
  assert.equal(m.relocs[0].target.section.name, '.text');
  assert.equal(m.relocs[1].symbolName, '_Z3sumPii');
  assert.equal(m.annotations.find(a => a.start === 64).title, 'main');
  assertContiguousAnnotations(m);

  const sum = P.parse(fixture('rel-sum.o'));
  assert.equal(sum.valid, true);
  assert.equal(sum.sections.length, 12);
  assert.equal(sum.symbols.length, 5);
  assert.equal(sum.relocs.length, 2);
  assert.equal(sum.relocs[1].target.section.name, '.eh_frame');
  assertContiguousAnnotations(sum);
});

test('malformed input fails gracefully', () => {
  const notElf = P.parse(Buffer.from('hello world'));
  assert.equal(notElf.valid, false);
  assert.ok(notElf.errors.length > 0);

  const tiny = P.parse(Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  assert.equal(tiny.valid, false);

  const truncated = P.parse(fixture('demo.elf').subarray(0, 100));
  assert.equal(truncated.valid, true);
  assert.ok(truncated.warnings.length > 0);
  assertContiguousAnnotations(truncated);
});

test('entry field lookup and relocation naming helpers', () => {
  assert.equal(P.fieldForEntryOffset('symbol', 64, 8).key, 'st_value');
  assert.equal(P.fieldForEntryOffset('symbol', 32, 8).key, 'st_size');
  assert.equal(P.fieldForEntryOffset('rela', 64, 16).key, 'r_addend');
  assert.equal(P.fieldForEntryOffset('dyn', 32, 4).key, 'd_val');
  assert.equal(P.relocTypeName(62, 8), 'R_X86_64_RELATIVE');
  assert.equal(P.relocTypeName(3, 8), 'R_386_RELATIVE');
  assert.equal(P.relocTypeName(183, 1027), 'R_AARCH64_RELATIVE');
  assert.equal(P.relocTypeName(62, 9999), 'R_EM_X86_64_9999');
});
