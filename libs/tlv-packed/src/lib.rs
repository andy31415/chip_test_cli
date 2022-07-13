use streaming_iterator::StreamingIterator;
use tlv_stream::Record;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DecodeError {
    InvalidData,    // failed to decode some data
    InvalidNesting, // mismatched start/end structures
    Internal,       // Internal logic error, should not happen
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DecodeEnd {
    StreamFinished, // stream of data returned None
    DataConsumed,   // read full value (single value or 'structure end')
}

pub trait TlvMergeDecodable<'a, Source>
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

pub trait TlvDecodable<'a, Source>
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
