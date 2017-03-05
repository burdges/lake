

trait Bytes {
    type Bytes;
    fn to_bytes(&Self) -> Bytes;
    fn from_bytes(&Bytes) -> Self;
}

impl PacketName {
    type Bytes = [u8; PACKET_NAME_LENGTH];
}


