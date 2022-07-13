use lazy_static::lazy_static;
use proc_macro::TokenStream;
use quote::quote;
use regex::{Match, Regex};
use streaming_iterator::{convert, StreamingIterator};
use syn::ExprLit;
use tlv_stream::{ContainerType, Record, Value};

#[derive(Debug, Copy, Clone, PartialEq)]
enum DecodeError {
    InvalidData,    // failed to decode some data
    InvalidNesting, // mismatched start/end structures
    Internal,       // Internal logic error, should not happen
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DecodeEnd {
    StreamFinished, // stream of data returned None
    DataConsumed,   // read full value (single value or 'structure end')
}

trait TlvMergeDecodable<'a, Source>
where
    Source: StreamingIterator<Item = Record<'a>>,
    Self: Default,
{
    /// Merge-decode the current value.
    ///
    /// Arguments:
    ///
    /// * `source` is the iterator that MUST have been advanced to the current record
    ///   to decode. Decoding ignores the current tag, but will validate the data.
    ///
    /// Notes:
    ///   - `source` MUST have been already advanced via `next`
    ///   - For containers (structures, lists, arrays), source MUST end up with a
    ///     Container end otherwise it is considered an error.
    ///
    ///
    ///
    fn merge_decode(&mut self, source: &mut Source) -> Result<DecodeEnd, DecodeError>;
}

trait TlvDecodable<'a, Source>
where
    Source: StreamingIterator<Item = Record<'a>>,
    Self: Sized,
{
    /// Decode the current value from a stream
    ///
    /// Arguments:
    ///
    /// * `source` is the iterator that is NOT advanced yet.
    ///   Iterator data MUST NOT be enclosed by start/end structure
    fn decode(source: &mut Source) -> Result<Self, DecodeError>;
}

/// decodes a single value from a streaming iterator.
///
/// Assumes that the iterator has already been positioned to a valid location.
impl<'a, BaseType, Source, E> TlvMergeDecodable<'a, Source> for BaseType
where
    Source: StreamingIterator<Item = Record<'a>>,
    BaseType: std::convert::TryFrom<tlv_stream::Value<'a>, Error = E> + Sized + Default,
{
    fn merge_decode(&mut self, source: &mut Source) -> Result<DecodeEnd, DecodeError> {
        // The decoding is assumed to be already positioned to the right location
        match source.get() {
            None => Err(DecodeError::InvalidData),
            Some(record) => {
                *self = record
                    .value
                    .try_into()
                    .map_err(|_| DecodeError::InvalidData)?;
                Ok(DecodeEnd::DataConsumed)
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq)]
struct ChildStructure {
    some_unsigned: Option<u32>, // tag: 1
    some_signed: i16,           // tag: 2
}

fn wrap_structure<'a, Source>(source: Source) -> impl StreamingIterator<Item = Record<'a>>
where
    Source: StreamingIterator<Item = Record<'a>>,
{
    let strucure_begin = convert([Record {
        tag: tlv_stream::TagValue::Anonymous,
        value: Value::ContainerStart(ContainerType::Structure),
    }]);

    let structure_end = convert([Record {
        tag: tlv_stream::TagValue::Anonymous,
        value: Value::ContainerEnd,
    }]);

    let mut source = strucure_begin.chain(source).chain(structure_end).fuse();
    source.next();

    source
}

impl<'a, Source> TlvDecodable<'a, Source> for ChildStructure
where
    Source: StreamingIterator<Item = Record<'a>>,
{
    /// Decodes the current value from a stream
    ///
    /// `source` MUST NOT be wrapped in structure start/end already (decoding does this
    /// automatically)
    fn decode(source: &mut Source) -> Result<Self, DecodeError> {
        let mut result = Self::default();
        let mut source = wrap_structure(source);

        match result.merge_decode(&mut source)? {
            DecodeEnd::StreamFinished => Err(DecodeError::InvalidNesting),
            DecodeEnd::DataConsumed => match source.next() {
                Some(_) => Err(DecodeError::InvalidNesting),
                None => Ok(result),
            },
        }
    }
}

/*
impl<'a, Source> TlvMergeDecodable<'a, Source> for ::core::option::Option<ChildStructure>
where
    Source: StreamingIterator<Item = Record<'a>>
{
    fn merge_decode(&mut self, source: &mut Source) -> Result<DecodeEnd, DecodeError> {
        if matches!(self, None) {
            *self = Some(Default::default())
        }

        match self {
            Some(ref mut value) => value.merge_decode(source)?,
            None => return Err(DecodeError::Internal), // this should NEVER happen
        }
    }
}
*/

impl<'a, Source> TlvMergeDecodable<'a, Source> for ChildStructure
where
    Source: StreamingIterator<Item = Record<'a>>,
{
    fn merge_decode(&mut self, source: &mut Source) -> Result<DecodeEnd, DecodeError> {
        if !matches!(
            source.get(),
            Some(Record {
                tag: _,
                value: Value::ContainerStart(ContainerType::Structure)
            })
        ) {
            return Err(DecodeError::InvalidData);
        }

        loop {
            let record = source.next();

            let record = match record {
                None => return Ok(DecodeEnd::StreamFinished),
                Some(Record {
                    tag: _,
                    value: Value::ContainerEnd,
                }) => return Ok(DecodeEnd::DataConsumed),
                Some(value) => value,
            };

            let decoded = match record.tag {
                tlv_stream::TagValue::ContextSpecific { tag: 1 } => {
                    self.some_unsigned.merge_decode(source)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 2 } => {
                    self.some_signed.merge_decode(source)?
                }
                _ => DecodeEnd::DataConsumed, // TODO: should we log skipped entry?
            };
            if decoded == DecodeEnd::StreamFinished {
                return Err(DecodeError::InvalidNesting);
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Default)]
struct TopStructure<'a> {
    some_nr: Option<u32>, // tag: 1
    some_str: &'a str,    // tag: 2
    some_signed: i16,     // tag: 3

    child: ChildStructure, // tag 4
    child2: Option<ChildStructure>, // tag 5

                           // TODO: array or list ?
}

impl<'a, Source> TlvDecodable<'a, Source> for TopStructure<'a>
where
    Source: StreamingIterator<Item = Record<'a>>,
{
    /// Decodes the current value from a stream
    ///
    /// `source` MUST NOT be wrapped in structure start/end already (decoding does this
    /// automatically)
    fn decode(source: &mut Source) -> Result<Self, DecodeError> {
        let mut result = Self::default();
        let mut source = wrap_structure(source);

        match result.merge_decode(&mut source)? {
            DecodeEnd::StreamFinished => Err(DecodeError::InvalidNesting),
            DecodeEnd::DataConsumed => match source.next() {
                Some(_) => Err(DecodeError::InvalidNesting),
                None => Ok(result),
            },
        }
    }
}

impl<'a, Source> TlvMergeDecodable<'a, Source> for TopStructure<'a>
where
    Source: StreamingIterator<Item = Record<'a>>,
{
    fn merge_decode(&mut self, source: &mut Source) -> Result<DecodeEnd, DecodeError> {
        if !matches!(
            source.get(),
            Some(Record {
                tag: _,
                value: Value::ContainerStart(ContainerType::Structure)
            })
        ) {
            return Err(DecodeError::InvalidData);
        }

        loop {
            let record = source.next();

            let record = match record {
                None => return Ok(DecodeEnd::StreamFinished),
                Some(Record {
                    tag: _,
                    value: Value::ContainerEnd,
                }) => return Ok(DecodeEnd::DataConsumed),
                Some(value) => value,
            };

            let decoded = match record.tag {
                tlv_stream::TagValue::ContextSpecific { tag: 1 } => {
                    self.some_nr.merge_decode(source)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 2 } => {
                    self.some_str.merge_decode(source)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 3 } => {
                    self.some_signed.merge_decode(source)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 4 } => {
                    self.child.merge_decode(source)?
                }
                tlv_stream::TagValue::ContextSpecific { tag: 5 } => {
                    if self.child2 == None {
                        self.child2 = Some(Default::default());
                    }

                    match self.child2 {
                        Some(ref mut value) => value.merge_decode(source)?,
                        None => return Err(DecodeError::Internal),
                    }
                }
                _ => DecodeEnd::DataConsumed, // TODO: log here?
            };
            if decoded != DecodeEnd::DataConsumed {
                return Err(DecodeError::InvalidNesting);
            }
        }
    }
}

fn parse_u32_match(m: Option<Match>) -> anyhow::Result<u32> {
    let value = m
        .ok_or_else(|| anyhow::anyhow!("Unable to capture number"))?
        .as_str();

    let value = if value.starts_with("0x") {
        u32::from_str_radix(&value[2..], 16)?
    } else {
        value.parse::<u32>()?
    };

    Ok(value)
}

fn parse_u16_match(m: Option<Match>) -> anyhow::Result<u16> {
    let value = m
        .ok_or_else(|| anyhow::anyhow!("Unable to capture number"))?
        .as_str();

    let value = if value.starts_with("0x") {
        u16::from_str_radix(&value[2..], 16)?
    } else {
        value.parse::<u16>()?
    };

    Ok(value)
}


/// Parses a string tag value into an underlying
/// [::tlvstream::TagValue] that can be used for macro generation
///
/// Valid syntax examples:
///   - "context: 123"
///   - "context: 0xabc"
///   - "CONTEXt: 22"
///
fn parse_tag_value(tag: &str) -> Result<TokenStream, anyhow::Error> {
    lazy_static! {
        static ref RE_CONTEXT: Regex =
            Regex::new(r"^(?i)context:\s*(\d+|0x[[:xdigit:]]+)$").unwrap();
        static ref RE_IMPLICIT: Regex =
            Regex::new(r"^(?i)implicit:\s*(\d+|0x[[:xdigit:]]+)$").unwrap();
        static ref RE_FULL: Regex = Regex::new(
            r"^(?i)full:\s*(?:(\d+|0x[[:xdigit:]]+)-(\d+|0x[[:xdigit:]]+)-)?(\d+|0x[[:xdigit:]]+)$"
        )
        .unwrap();
    }

    if tag.eq_ignore_ascii_case("anonymous") {
        return Ok(quote! {
            ::tlv_stream::TagValue::Anonymous
        }
        .into());
    }

    if let Some(captures) = RE_CONTEXT.captures(tag) {
        let tag = parse_u32_match(captures.get(1))?;

        return Ok(quote! {
            ::tlv_stream::TagValue::ContextSpecific { tag: #tag}
        }
        .into());
    }

    if let Some(captures) = RE_IMPLICIT.captures(tag) {
        let tag = parse_u32_match(captures.get(1))?;

        return Ok(quote! {
            ::tlv_stream::TagValue::Implicit { tag: #tag}
        }
        .into());
    }
    if let Some(captures) = RE_FULL.captures(tag) {
        let tag = parse_u32_match(captures.get(3))?;

        if captures.get(1).is_some() {
            let vendor_id = parse_u16_match(captures.get(1))?;
            let profile_id = parse_u16_match(captures.get(2))?;

            return Ok(quote! {
                ::tlv_stream::TagValue::Full { vendor_id: #vendor_id, profile_id: #profile_id, tag: #tag}
            }.into());
        } else {
            return Ok(quote! {
                ::tlv_stream::TagValue::Full { vendor_id: 0, profile_id: 0, tag: #tag}
            }
            .into());
        }
    }

    return Err(anyhow::anyhow!("Invalid tag syntax: '{}'", tag));
}

/// Converts strings from tag value.
///
/// Generally used for internal testing of parsing metadata strings
///
/// ```
/// use tlv_structs::into_parsed_tag_value;
/// use tlv_stream::TagValue;
///
/// assert_eq!(
///     into_parsed_tag_value!("CONTEXT:123"),
///     TagValue::ContextSpecific { tag: 123 }
/// );
///
/// assert_eq!(
///     into_parsed_tag_value!("context: 22"),
///     TagValue::ContextSpecific { tag: 22 }
/// );
///
/// assert_eq!(
///     into_parsed_tag_value!("context: 0x12"),
///     TagValue::ContextSpecific { tag: 18 }
/// );
///
/// assert_eq!(
///     into_parsed_tag_value!("context: 0xabcd"),
///     TagValue::ContextSpecific { tag: 0xabcd }
/// );
///
/// assert_eq!(
///     into_parsed_tag_value!("implicit: 0x1234"),
///     TagValue::Implicit { tag: 0x1234 }
/// );
///
/// assert_eq!(
///     into_parsed_tag_value!("Anonymous"),
///     TagValue::Anonymous
/// );
///
/// assert_eq!(
///     into_parsed_tag_value!("ANONYMOUS"),
///     TagValue::Anonymous
/// );
///
/// assert_eq!(
///     into_parsed_tag_value!("full: 1234"),
///     TagValue::Full { vendor_id: 0, profile_id: 0, tag: 1234 }
/// );
///
/// assert_eq!(
///     into_parsed_tag_value!("full: 0x1122-1-0x1234"),
///     TagValue::Full { vendor_id: 0x1122, profile_id: 1, tag: 0x1234 }
/// );
/// ```
///
/// It invalid values are passed, the parsing will panic
///
/// ```compile_fail
/// use tlv_structs::into_parsed_tag_value;
/// into_parsed_tag_value!("something else");
/// ```
///
/// ```compile_fail
/// use tlv_structs::into_parsed_tag_value;
/// into_parsed_tag_value!("context: notahexvalue");
/// ```
///
#[proc_macro]
pub fn into_parsed_tag_value(input: TokenStream) -> TokenStream {
    let item: ExprLit = syn::parse(input).unwrap();

    match item.lit {
        syn::Lit::Str(s) => parse_tag_value(s.value().as_str()).unwrap(),
        _ => panic!("Need a string literal to parse"),
    }
}

#[cfg(test)]
mod tests {
    use tlv_stream::{ContainerType, Record, TagValue, Value};

    use crate::{TlvDecodable, TlvMergeDecodable, TopStructure};

    #[test]
    fn decode_test() {
        let s = TopStructure::default();

        assert_eq!(s.some_str, "");
        assert_eq!(s.some_nr, None);
        assert_eq!(s.some_signed, 0);

        let records = [
            Record {
                tag: TagValue::ContextSpecific { tag: 1 },
                value: Value::Unsigned(123),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 2 },
                value: Value::Utf8(&[65, 66, 67]),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 3 },
                value: Value::Signed(-2),
            },
        ];
        let mut streamer = streaming_iterator::convert(records.iter().copied());

        let s = TopStructure::decode(&mut streamer).unwrap();

        assert_eq!(s.some_nr, Some(123));
        assert_eq!(s.some_str, "ABC");
        assert_eq!(s.some_signed, -2);
    }

    #[test]
    fn nested_decode() {
        let records = [
            Record {
                tag: TagValue::ContextSpecific { tag: 1 },
                value: Value::Unsigned(123),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 2 },
                value: Value::Utf8(&[65, 66, 67]),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 3 },
                value: Value::Signed(-2),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 4 },
                value: Value::ContainerStart(ContainerType::Structure),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 1 },
                value: Value::Unsigned(21),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 2 },
                value: Value::Signed(-12),
            },
            Record {
                tag: TagValue::Anonymous,
                value: Value::ContainerEnd,
            },
        ];
        let mut streamer = streaming_iterator::convert(records.iter().copied());

        let mut s = TopStructure::decode(&mut streamer).unwrap();

        assert_eq!(s.some_nr, Some(123));
        assert_eq!(s.some_str, "ABC");
        assert_eq!(s.some_signed, -2);
        assert_eq!(s.child.some_signed, -12);
        assert_eq!(s.child.some_unsigned, Some(21));
        assert_eq!(s.child2, None);

        let records = [
            Record {
                tag: TagValue::ContextSpecific { tag: 5 },
                value: Value::ContainerStart(ContainerType::Structure),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 1 },
                value: Value::Unsigned(22),
            },
            Record {
                tag: TagValue::ContextSpecific { tag: 2 },
                value: Value::Signed(23),
            },
            Record {
                tag: TagValue::Anonymous,
                value: Value::ContainerEnd,
            },
        ];
        let mut streamer =
            super::wrap_structure(streaming_iterator::convert(records.iter().copied()));
        s.merge_decode(&mut streamer).unwrap();

        assert_eq!(s.child2.unwrap().some_signed, 23);
        assert_eq!(s.child2.unwrap().some_unsigned, Some(22));
    }
}
