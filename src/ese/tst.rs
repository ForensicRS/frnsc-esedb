use std::io::Write;

use super::header::Header;

pub fn load_mdb_to_memory() -> Vec<u8> {
    std::fs::read("./artifacts/SystemIdentity.mdb").unwrap()
}


pub fn get_mdb_and_header() -> (Vec<u8>, Header) {
    let db: Vec<u8> = std::fs::read("./artifacts/SystemIdentity.mdb").unwrap();
    let header = Header::from_buff(&db).unwrap();
    (db, header)
}

pub fn get_mdb_and_header_ual() -> (Vec<u8>, Header) {
    let db: Vec<u8> = std::fs::read("./artifacts/UAL/UAL/SystemIdentity.mdb").unwrap();
    let header = Header::from_buff(&db).unwrap();
    (db, header)
}

pub fn to_debug_file<W: Write>(file : &mut W, name : &str, data : String) {
    file.write_all(b"----------").unwrap();
    file.write_all(name.as_bytes()).unwrap();
    file.write_all(b"----------\n").unwrap();
    file.write_all(data.as_bytes()).unwrap();
    file.write_all(b"\n").unwrap();
}

pub fn open_debug_file(name : &str) -> std::fs::File {
    std::fs::File::create(format!("./artifacts/{}.log", name)).unwrap()
}