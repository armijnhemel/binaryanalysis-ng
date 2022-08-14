CREATE TABLE IF NOT EXISTS dex_bytecode(dex_sha256 text, class_name text, method_name text, bytecode_sha256 text, bytecode_tlsh text);
CREATE INDEX dex_bytecode_dex_sha256 ON dex_bytecode(dex_sha256);
CREATE INDEX dex_bytecode_bytecode_sha256 ON dex_bytecode(bytecode_sha256);
CREATE INDEX dex_bytecode_bytecode_tlsh ON dex_bytecode(bytecode_tlsh);
