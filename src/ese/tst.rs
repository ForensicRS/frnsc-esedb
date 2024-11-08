use super::header::Header;

pub fn load_mdb_to_memory() -> Vec<u8> {
    std::fs::read("./artifacts/SystemIdentity.mdb").unwrap()
}


pub fn get_mdb_and_header() -> (Vec<u8>, Header) {
    let db: Vec<u8> = std::fs::read("./artifacts/SystemIdentity.mdb").unwrap();
    let header = Header::from_buff(&db).unwrap();
    (db, header)
}