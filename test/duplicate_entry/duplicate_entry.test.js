"use strict";

// GHSA-p634-w6r4-rjp2: an archive may declare the same entry name twice.
// adm-zip kept every entry in its list but only the last one in its name table,
// so getEntry()/readFile() (table) and getEntries()/extractAllTo() (list)
// resolved the same name to different content: an application validating
// "a.txt" via getEntry() approved one payload while another one was extracted.
// Such ambiguous archives are now rejected when the entries are read.

const assert = require("assert");
const Zip = require("../../adm-zip");

const DUPLICATE = /Duplicate entry name/;

// Builds an archive holding "a.txt" ("FIRST") and "b.txt" ("SECOND"), then
// renames the second entry to "a.txt" in both its local and central header.
function makeDuplicateArchive() {
    const zip = new Zip();
    zip.addFile("a.txt", Buffer.from("FIRST"));
    zip.addFile("b.txt", Buffer.from("SECOND"));
    const buf = Buffer.from(zip.toBuffer());

    const from = Buffer.from("b.txt");
    const to = Buffer.from("a.txt");
    let replaced = 0;
    let pos = buf.indexOf(from);
    while (pos !== -1) {
        to.copy(buf, pos);
        replaced++;
        pos = buf.indexOf(from, pos + from.length);
    }
    // exactly one local file header and one central directory header
    assert.strictEqual(replaced, 2);
    return buf;
}

// Stand-in filesystem: any access means extraction got past archive parsing.
function untouchableFs() {
    const fail = () => {
        throw new Error("filesystem was accessed");
    };
    const fs = {};
    ["statSync", "existsSync", "mkdirSync", "openSync", "writeSync", "closeSync", "chmodSync", "utimesSync"].forEach((m) => (fs[m] = fail));
    ["stat", "exists", "mkdir", "open", "write", "close", "chmod", "utimes"].forEach((m) => (fs[m] = fail));
    return fs;
}

describe("ADM-ZIP - duplicate entry names (GHSA-p634-w6r4-rjp2)", () => {
    it("still reads an archive whose entry names are distinct", () => {
        const zip = new Zip();
        zip.addFile("a.txt", Buffer.from("FIRST"));
        zip.addFile("b.txt", Buffer.from("SECOND"));
        const reopened = new Zip(zip.toBuffer());
        assert.deepStrictEqual(
            reopened.getEntries().map((e) => e.entryName),
            ["a.txt", "b.txt"]
        );
        assert.strictEqual(reopened.test(), true);
        assert.strictEqual(reopened.readFile("a.txt").toString(), "FIRST");
        assert.strictEqual(reopened.readFile("b.txt").toString(), "SECOND");
    });

    it("rejects the archive when entries are listed", () => {
        const buf = makeDuplicateArchive();
        assert.throws(() => new Zip(buf).getEntries(), DUPLICATE);
        assert.throws(() => new Zip(buf, { readEntries: true }), DUPLICATE);
    });

    it("getEntry() / readFile() cannot be used to approve one of the duplicates", () => {
        const buf = makeDuplicateArchive();
        assert.throws(() => new Zip(buf).getEntry("a.txt"), DUPLICATE);
        assert.throws(() => new Zip(buf).readFile("a.txt"), DUPLICATE);
    });

    it("extractAllTo() refuses the archive before writing anything", () => {
        const zip = new Zip(makeDuplicateArchive(), { fs: untouchableFs() });
        assert.throws(() => zip.extractAllTo("never-written", false), DUPLICATE);
    });

    it("extractAllToAsync() refuses the archive before writing anything", () => {
        const zip = new Zip(makeDuplicateArchive(), { fs: untouchableFs() });
        return assert.rejects(zip.extractAllToAsync("never-written", false), DUPLICATE);
    });
});
