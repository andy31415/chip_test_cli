use tlv_stream::TagValue;
use tlv_structs::into_parsed_tag_value;

#[test]
fn test_parsed_tag_values() {
    assert_eq!(
        into_parsed_tag_value!("context: 12"),
        TagValue::ContextSpecific { tag: 12 }
    );

    assert_eq!(
        into_parsed_tag_value!("context: 22"),
        TagValue::ContextSpecific { tag: 22 }
    );
}
