CREATE TABLE IF NOT EXISTS elf_hashes(sha256 text, tlsh text, telfhash text);
CREATE UNIQUE INDEX elf_hashes_sha256 ON elf_hashes(sha256);
CREATE INDEX elf_hashes_telfhash ON elf_hashes(telfhash);
