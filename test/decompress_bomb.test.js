"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of payload. The crc defaults to 0, which is
// deliberately wrong (alloc used to happen before the crc check); pass the real
// crc of the uncompressed data to build an otherwise well-formed entry.
function craftBomb(declaredSize, method, content, crc = 0) {
    const name = Buffer.from("a");
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// Regression test for CVE-2026-92000 (GHSA-c6fg-446q-cg94):
// the decompression cap from CVE-2026-39244 only reached the sync path. The
// async path (getDataAsync -> zlib stream) ignores maxOutputLength, so a small
// deflate stream expanded without limit regardless of the declared size, and a
// declared uncompressed size of 0 disabled the cap on both paths. Output must be
// bounded by the declared size on every path, with 0 meaning "empty".
describe("decompression output cap (async path / zero declared size) - CVE-2026-92000", () => {
    const zlib = require("zlib");
    const Utils = require("../util");
    const nodeMajor = +process.versions.node.split(".")[0];

    // ~1 MB of highly compressible data deflates to ~1 KB: a small amplification bomb
    const BOMB = Buffer.alloc(1024 * 1024, 0x41);
    const BOMB_DEFLATED = zlib.deflateRawSync(BOMB);
    // a valid crc, so without the cap the oversized output would be accepted as-is
    const BOMB_CRC = Utils.crc32(BOMB);

    // Calls getDataAsync and resolves with every callback invocation seen within a
    // short window, so tests can assert the callback fires exactly once.
    function readAsync(entry, cb) {
        const calls = [];
        entry.getDataAsync((data, err) => calls.push({ data, err }));
        setTimeout(() => cb(calls), 200);
    }

    it("async read rejects output larger than the declared size", (done) => {
        const zip = new Zip(craftBomb(10, 8 /* DEFLATED */, BOMB_DEFLATED, BOMB_CRC));
        readAsync(zip.getEntries()[0], (calls) => {
            try {
                expect(calls).to.have.lengthOf(1);
                expect(calls[0].err, "oversized async output must fail").to.be.an("error");
                expect(calls[0].err.message).to.match(/exceeds the declared uncompressed size/);
                expect(calls[0].data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("async read rejects non-empty output when the declared size is 0", (done) => {
        const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, BOMB_DEFLATED, BOMB_CRC));
        readAsync(zip.getEntries()[0], (calls) => {
            try {
                expect(calls).to.have.lengthOf(1);
                expect(calls[0].err, "declared size 0 must not disable the cap").to.be.an("error");
                expect(calls[0].err.message).to.match(/exceeds the declared uncompressed size/);
                expect(calls[0].data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("async readFileAsync is capped as well", (done) => {
        const zip = new Zip(craftBomb(10, 8 /* DEFLATED */, BOMB_DEFLATED, BOMB_CRC));
        zip.readFileAsync(zip.getEntries()[0], (data, err) => {
            try {
                expect(err, "readFileAsync must surface the cap error").to.be.an("error");
                expect(err.message).to.match(/exceeds the declared uncompressed size/);
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("sync read rejects non-empty output when the declared size is 0", function () {
        // the sync cap relies on zlib's maxOutputLength, available from Node 15
        if (nodeMajor < 15) this.skip();
        const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, BOMB_DEFLATED, BOMB_CRC));
        expect(() => zip.getEntries()[0].getData()).to.throw();
    });

    it("still reads an empty DEFLATED entry declared with size 0", (done) => {
        const empty = zlib.deflateRawSync(Buffer.alloc(0));
        const zip = new Zip(craftBomb(0, 8 /* DEFLATED */, empty, 0));
        const entry = zip.getEntries()[0];
        expect(entry.getData().length).to.equal(0);
        readAsync(entry, (calls) => {
            try {
                expect(calls).to.have.lengthOf(1);
                expect(calls[0].err).to.equal(undefined);
                expect(calls[0].data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads a legitimate DEFLATED entry asynchronously at exactly its declared size", (done) => {
        const zip = new Zip(craftBomb(BOMB.length, 8 /* DEFLATED */, BOMB_DEFLATED, BOMB_CRC));
        readAsync(zip.getEntries()[0], (calls) => {
            try {
                expect(calls).to.have.lengthOf(1);
                expect(calls[0].err).to.equal(undefined);
                expect(calls[0].data.equals(BOMB)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still round-trips a DEFLATED entry through getDataAsync", (done) => {
        const payload = Buffer.from("hello world ".repeat(5000));
        const zip = new Zip();
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        round.getEntry("d.txt").getDataAsync((data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });
});
