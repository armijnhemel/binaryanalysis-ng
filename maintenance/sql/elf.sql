CREATE TABLE IF NOT EXISTS elf_hashes(sha256 text, tlsh text, telfhash text);
CREATE INDEX elf_hashes_sha256 ON elf_hashes USING HASH (sha256);
