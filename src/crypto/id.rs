use uuid::{Uuid, timestamp::Timestamp};

pub fn new_id() -> String {
    let ts = Timestamp::now(uuid::NoContext);
    let node_id: [u8; 6] = rand::random();
    Uuid::new_v6(ts, &node_id).to_string()
}
