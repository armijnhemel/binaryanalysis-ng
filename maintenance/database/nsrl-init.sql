create table if not exists nsrl_hash(sha1 text, md5 text, filename text, primary key(sha1));
create table if not exists nsrl_entry(sha1 text, productcode int);
create table if not exists nsrl_manufacturer(manufacturercode int, manufacturername text, primary key(manufacturercode));
create table if not exists nsrl_os(oscode int, osname text, osversion text, manufacturercode int, primary key(oscode));
create table if not exists nsrl_product(productcode int, productname text, productversion text, manufacturercode int, applicationtype text, primary key(productcode));
