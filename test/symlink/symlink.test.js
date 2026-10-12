"use strict";

// CVE-2026-76845: extraction followed symbolic links that already existed in the
// extraction target. sanitize() only checks the textual path, and writeFileTo /
// writeFileToAsync / makeDir open and create through whatever is on disk, so an
// entry "link/file" (where target/link -> /elsewhere) or an entry "file" (where
// target/file -> /elsewhere/file, with overwrite on) wrote attacker-controlled
// content outside the extraction root. Every path component below the root is
// now checked and a symlink there aborts the extraction with FILE_IN_THE_WAY.

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");

const IN_THE_WAY = /file in the way/i;
const isWin = process.platform === "win32";

describe("ADM-ZIP - symlinks inside the extraction target (CVE-2026-76845)", () => {
    let base, outside, target, victim;

    beforeEach(() => {
        base = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-symlink-"));
        outside = pth.join(base, "outside");
        target = pth.join(base, "target");
        victim = pth.join(outside, "victim.txt");
        fs.mkdirSync(outside);
        fs.mkdirSync(target);
        fs.writeFileSync(victim, "ORIGINAL");
    });

    // rimraf unlinks symlinks/junctions instead of descending into them
    afterEach(() => rimraf.sync(base));

    // target/<name> -> outside (a directory link; junctions need no privilege on Windows)
    function linkDir(ctx, name) {
        const link = pth.join(target, name);
        try {
            fs.symlinkSync(pth.resolve(outside), link, isWin ? "junction" : "dir");
        } catch (e) {
            ctx.skip(); // symlinks unavailable on this platform/account
        }
        expect(fs.lstatSync(link).isSymbolicLink()).to.equal(true);
        return link;
    }

    // target/<name> -> outside/victim.txt (a file link)
    function linkFile(ctx, name) {
        const link = pth.join(target, name);
        try {
            fs.symlinkSync(pth.resolve(victim), link, "file");
        } catch (e) {
            ctx.skip(); // file symlinks need extra privileges on Windows
        }
        expect(fs.lstatSync(link).isSymbolicLink()).to.equal(true);
        return link;
    }

    function makeZip(entries) {
        const zip = new Zip();
        entries.forEach((e) => zip.addFile(e.name, e.content === undefined ? null : Buffer.from(e.content)));
        return new Zip(zip.toBuffer());
    }

    function expectOutsideUntouched() {
        expect(fs.readdirSync(outside)).to.deep.equal(["victim.txt"]);
        expect(fs.readFileSync(victim, "utf8")).to.equal("ORIGINAL");
    }

    describe("extractAllTo", () => {
        it("does not write a file through a symlinked directory", function () {
            linkDir(this, "link");
            const zip = makeZip([{ name: "link/pwned.txt", content: "PWNED" }]);

            expect(() => zip.extractAllTo(target, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "pwned.txt"))).to.equal(false);
            expectOutsideUntouched();
        });

        it("does not create a directory through a symlinked directory", function () {
            linkDir(this, "link");
            const zip = makeZip([{ name: "link/sub/" }, { name: "link/sub/pwned.txt", content: "PWNED" }]);

            expect(() => zip.extractAllTo(target, true)).to.throw(IN_THE_WAY);
            expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
            expectOutsideUntouched();
        });

        it("does not overwrite the target of a symlinked file", function () {
            linkFile(this, "victim.txt");
            const zip = makeZip([{ name: "victim.txt", content: "PWNED" }]);

            expect(() => zip.extractAllTo(target, true)).to.throw(IN_THE_WAY);
            expectOutsideUntouched();
        });
    });

    describe("extractEntryTo", () => {
        it("does not write a file entry through a symlinked directory", function () {
            linkDir(this, "link");
            const zip = makeZip([{ name: "link/pwned.txt", content: "PWNED" }]);

            expect(() => zip.extractEntryTo("link/pwned.txt", target, true, true)).to.throw(IN_THE_WAY);
            expectOutsideUntouched();
        });

        it("does not write through a symlinked directory named by outFileName", function () {
            linkDir(this, "link");
            const zip = makeZip([{ name: "a.txt", content: "PWNED" }]);

            expect(() => zip.extractEntryTo("a.txt", target, true, true, false, "link/pwned.txt")).to.throw(IN_THE_WAY);
            expectOutsideUntouched();
        });

        it("does not write the children of a directory entry through a symlinked directory", function () {
            linkDir(this, "link");
            const zip = makeZip([{ name: "link/" }, { name: "link/pwned.txt", content: "PWNED" }]);

            expect(() => zip.extractEntryTo("link/", target, true, true)).to.throw(IN_THE_WAY);
            expectOutsideUntouched();
        });

        it("does not overwrite the target of a symlinked file", function () {
            linkFile(this, "victim.txt");
            const zip = makeZip([{ name: "victim.txt", content: "PWNED" }]);

            expect(() => zip.extractEntryTo("victim.txt", target, true, true)).to.throw(IN_THE_WAY);
            expectOutsideUntouched();
        });
    });

    describe("extractAllToAsync", () => {
        it("does not write a file through a symlinked directory (callback)", function (done) {
            linkDir(this, "link");
            const zip = makeZip([{ name: "link/pwned.txt", content: "PWNED" }]);

            zip.extractAllToAsync(target, true, false, (err) => {
                try {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(IN_THE_WAY);
                    expect(fs.existsSync(pth.join(outside, "pwned.txt"))).to.equal(false);
                    expectOutsideUntouched();
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });

        it("does not create a directory through a symlinked directory (promise)", function () {
            linkDir(this, "link");
            const zip = makeZip([{ name: "link/sub/" }]);

            return zip.extractAllToAsync(target, true, false).then(
                () => {
                    throw new Error("extraction through the symlink was not rejected");
                },
                (err) => {
                    expect(err).to.be.an("error");
                    expect(fs.existsSync(pth.join(outside, "sub"))).to.equal(false);
                    expectOutsideUntouched();
                }
            );
        });

        it("does not overwrite the target of a symlinked file (promise)", function () {
            linkFile(this, "victim.txt");
            const zip = makeZip([{ name: "victim.txt", content: "PWNED" }]);

            return zip.extractAllToAsync(target, true, false).then(
                () => {
                    throw new Error("extraction through the symlink was not rejected");
                },
                (err) => {
                    expect(err.message).to.match(IN_THE_WAY);
                    expectOutsideUntouched();
                }
            );
        });
    });

    describe("legitimate extraction", () => {
        it("still extracts next to an unrelated symlink in the target", function () {
            linkDir(this, "link");
            const zip = makeZip([{ name: "dir/" }, { name: "dir/a.txt", content: "A" }, { name: "b.txt", content: "B" }]);

            zip.extractAllTo(target, true);
            expect(fs.readFileSync(pth.join(target, "dir", "a.txt"), "utf8")).to.equal("A");
            expect(fs.readFileSync(pth.join(target, "b.txt"), "utf8")).to.equal("B");
            expectOutsideUntouched();
        });

        it("still extracts when the target itself is reached through a symlink", function () {
            const rootLink = pth.join(base, "rootlink");
            try {
                fs.symlinkSync(pth.resolve(target), rootLink, isWin ? "junction" : "dir");
            } catch (e) {
                this.skip();
            }
            const zip = makeZip([{ name: "dir/a.txt", content: "A" }]);

            zip.extractAllTo(rootLink, true);
            zip.extractEntryTo("dir/a.txt", rootLink, false, true);
            expect(fs.readFileSync(pth.join(target, "dir", "a.txt"), "utf8")).to.equal("A");
            expect(fs.readFileSync(pth.join(target, "a.txt"), "utf8")).to.equal("A");
        });
    });
});
