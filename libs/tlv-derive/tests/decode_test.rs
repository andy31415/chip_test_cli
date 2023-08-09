#[macro_use]
extern crate tlv_derive;

use streaming_iterator::{convert, StreamingIterator};
use tlv_packed::{DecodeEnd, DecodeError, TlvDecodable, TlvMergeDecodable};
use tlv_stream::{ContainerType, Record, TagValue, Value};

#[derive(Debug, Copy, Clone, Default, PartialEq, TlvMergeDecodable)]
struct ChildStructure {
    #[tlv_tag = "context:1"]
    some_unsigned: Option<u32>,

    #[tlv_tag = "context:2"]
    some_signed: i16,
}

#[test]
fn test_simple_decode() {
    let mut s = ChildStructure::default();

    assert_eq!(s.some_unsigned, None);
    assert_eq!(s.some_signed, 0);

    let records = [
        Record {
            tag: TagValue::Anonymous,
            value: Value::ContainerStart(ContainerType::Structure),
        },
        Record {
            tag: TagValue::ContextSpecific { tag: 1 },
            value: Value::Unsigned(123),
        },
        Record {
            tag: TagValue::ContextSpecific { tag: 2 },
            value: Value::Signed(-2),
        },
        Record {
            tag: TagValue::Anonymous,
            value: Value::ContainerEnd,
        },
    ];

    let mut streamer = streaming_iterator::convert(records.iter().copied());

    // merge decode requires positioning at structure start
    streamer.next();
    s.merge_decode(&mut streamer).unwrap();

    assert_eq!(s.some_unsigned, Some(123));
    assert_eq!(s.some_signed, -2);
}
