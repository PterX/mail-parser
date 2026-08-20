/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */
#![doc = include_str!("../README.md")]
#![deny(rust_2018_idioms)]
#[forbid(unsafe_code)]
pub mod core;
pub mod decoders;
pub mod mailbox;
pub mod parsers;

use parsers::MessageStream;
use std::{borrow::Cow, collections::HashMap, hash::Hash, net::IpAddr};

/// RFC5322/RFC822 message parser.
#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(unpredictable_function_pointer_comparisons)]
pub struct MessageParser {
    pub(crate) header_map: HashMap<HeaderName<'static>, HdrParseFnc>,
    pub(crate) def_hdr_parse_fnc: HdrParseFnc,
}

pub(crate) type HdrParseFnc = for<'x> fn(&mut MessageStream<'x>) -> crate::HeaderValue<'x>;

/// An RFC5322/RFC822 message.
#[derive(Debug, Default, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Message<'x> {
    #[cfg_attr(feature = "serde", serde(default))]
    pub html_body: Vec<MessagePartId>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub text_body: Vec<MessagePartId>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub attachments: Vec<MessagePartId>,

    #[cfg_attr(feature = "serde", serde(default))]
    pub parts: Vec<MessagePart<'x>>,

    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Skip))]
    pub raw_message: Cow<'x, [u8]>,
}

/// MIME Message Part
#[derive(Debug, PartialEq, Default, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct MessagePart<'x> {
    #[cfg_attr(feature = "serde", serde(default))]
    pub headers: Vec<Header<'x>>,
    pub is_encoding_problem: bool,
    #[cfg_attr(feature = "serde", serde(default))]
    //#[cfg_attr(feature = "rkyv", rkyv(omit_bounds))]
    pub body: PartType<'x>,
    #[cfg_attr(feature = "serde", serde(skip))]
    pub encoding: Encoding,
    pub offset_header: u32,
    pub offset_body: u32,
    pub offset_end: u32,
}

/// MIME Part encoding type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
#[repr(u8)]
pub enum Encoding {
    #[default]
    None = 0,
    QuotedPrintable = 1,
    Base64 = 2,
}

impl From<u8> for Encoding {
    fn from(v: u8) -> Self {
        match v {
            1 => Encoding::QuotedPrintable,
            2 => Encoding::Base64,
            _ => Encoding::None,
        }
    }
}

/// Unique ID representing a MIME part within a message.
pub type MessagePartId = u32;

/// A text, binary or nested e-mail MIME message part.
///
/// - Text: Any text/* part
/// - Binary: Any other part type that is not text.
/// - Message: Nested RFC5322 message.
/// - MultiPart: Multipart part.
///
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
#[cfg_attr(
    feature = "rkyv",
    rkyv(serialize_bounds(
        __S: rkyv::ser::Writer + rkyv::ser::Allocator,
        __S::Error: rkyv::rancor::Source,
    ))
)]
#[cfg_attr(
    feature = "rkyv",
    rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))
)]
#[cfg_attr(
    feature = "rkyv",
    rkyv(bytecheck(
        bounds(
            __C: rkyv::validation::ArchiveContext,
        )
    ))
)]
pub enum PartType<'x> {
    /// Any text/* part
    Text(#[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::AsOwned))] Cow<'x, str>),

    /// A text/html part
    Html(#[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::AsOwned))] Cow<'x, str>),

    /// Any other part type that is not text.
    Binary(#[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::AsOwned))] Cow<'x, [u8]>),

    /// Any inline binary data that.
    InlineBinary(#[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::AsOwned))] Cow<'x, [u8]>),

    /// Nested RFC5322 message.
    Message(#[cfg_attr(feature = "rkyv", rkyv(omit_bounds))] Message<'x>),

    /// Multipart part
    Multipart(Vec<MessagePartId>),
}

impl Default for PartType<'_> {
    fn default() -> Self {
        PartType::Multipart(Vec::with_capacity(0))
    }
}

/// An RFC5322 or RFC2369 internet address.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Addr<'x> {
    /// The address name including comments
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub name: Option<Cow<'x, str>>,

    /// An e-mail address (RFC5322/RFC2369) or URL (RFC2369)
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub address: Option<Cow<'x, str>>,
}

/// An RFC5322 address group.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Group<'x> {
    /// Group name
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub name: Option<Cow<'x, str>>,

    /// Addresses member of the group
    #[cfg_attr(feature = "serde", serde(default))]
    pub addresses: Vec<Addr<'x>>,
}

/// A message header.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
#[cfg_attr(feature = "rkyv", rkyv(compare(PartialEq)))]
pub struct Header<'x> {
    pub name: HeaderName<'x>,
    pub value: HeaderValue<'x>,
    pub offset_field: u32,
    pub offset_start: u32,
    pub offset_end: u32,
}

macro_rules! header_names {
    ($($variant:ident = $id:literal, $name:literal, $lc:literal;)+) => {
        /// A header field
        #[derive(Debug, Clone, PartialOrd, Ord)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
        #[cfg_attr(
            feature = "rkyv",
            derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
        )]
        #[cfg_attr(feature = "rkyv", rkyv(compare(PartialEq)))]
        #[non_exhaustive]
        pub enum HeaderName<'x> {
            $($variant,)+
            Other(#[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::AsOwned))] Cow<'x, str>),
        }

        impl HeaderName<'_> {
            pub fn as_static_str(&self) -> &'static str {
                match self {
                    $(HeaderName::$variant => $name,)+
                    HeaderName::Other(_) => "",
                }
            }

            pub fn id(&self) -> u8 {
                match self {
                    $(HeaderName::$variant => $id,)+
                    HeaderName::Other(_) => 37,
                }
            }

            pub fn to_owned(&self) -> HeaderName<'static> {
                match self {
                    $(HeaderName::$variant => HeaderName::$variant,)+
                    HeaderName::Other(name) => HeaderName::Other(name.to_string().into()),
                }
            }

            pub fn into_owned(self) -> HeaderName<'static> {
                match self {
                    $(HeaderName::$variant => HeaderName::$variant,)+
                    HeaderName::Other(name) => HeaderName::Other(name.into_owned().into()),
                }
            }
        }

        pub(crate) fn header_map(name: &[u8]) -> Option<HeaderName<'static>> {
            hashify::tiny_map!(name,
                $($lc => HeaderName::$variant,)+
            )
        }

        #[cfg(feature = "rkyv")]
        impl ArchivedHeaderName<'_> {
            pub fn as_static_str(&self) -> &'static str {
                match self {
                    $(ArchivedHeaderName::$variant => $name,)+
                    ArchivedHeaderName::Other(_) => "",
                }
            }

            pub fn id(&self) -> u8 {
                match self {
                    $(ArchivedHeaderName::$variant => $id,)+
                    ArchivedHeaderName::Other(_) => 37,
                }
            }
        }

        #[cfg(feature = "rkyv")]
        impl From<&ArchivedHeaderName<'_>> for HeaderName<'static> {
            fn from(value: &ArchivedHeaderName<'_>) -> Self {
                match value {
                    $(ArchivedHeaderName::$variant => HeaderName::$variant,)+
                    ArchivedHeaderName::Other(name) => HeaderName::Other(name.to_string().into()),
                }
            }
        }
    };
}

header_names! {
    Subject = 0, "Subject", "subject";
    From = 1, "From", "from";
    To = 2, "To", "to";
    Cc = 3, "Cc", "cc";
    Date = 4, "Date", "date";
    Bcc = 5, "Bcc", "bcc";
    ReplyTo = 6, "Reply-To", "reply-to";
    Sender = 7, "Sender", "sender";
    Comments = 8, "Comments", "comments";
    InReplyTo = 9, "In-Reply-To", "in-reply-to";
    Keywords = 10, "Keywords", "keywords";
    Received = 11, "Received", "received";
    MessageId = 12, "Message-ID", "message-id";
    References = 13, "References", "references";
    ReturnPath = 14, "Return-Path", "return-path";
    MimeVersion = 15, "MIME-Version", "mime-version";
    ContentDescription = 16, "Content-Description", "content-description";
    ContentId = 17, "Content-ID", "content-id";
    ContentLanguage = 18, "Content-Language", "content-language";
    ContentLocation = 19, "Content-Location", "content-location";
    ContentTransferEncoding = 20, "Content-Transfer-Encoding", "content-transfer-encoding";
    ContentType = 21, "Content-Type", "content-type";
    ContentDisposition = 22, "Content-Disposition", "content-disposition";
    ResentTo = 23, "Resent-To", "resent-to";
    ResentFrom = 24, "Resent-From", "resent-from";
    ResentBcc = 25, "Resent-Bcc", "resent-bcc";
    ResentCc = 26, "Resent-Cc", "resent-cc";
    ResentSender = 27, "Resent-Sender", "resent-sender";
    ResentDate = 28, "Resent-Date", "resent-date";
    ResentMessageId = 29, "Resent-Message-ID", "resent-message-id";
    ListArchive = 30, "List-Archive", "list-archive";
    ListHelp = 31, "List-Help", "list-help";
    ListId = 32, "List-ID", "list-id";
    ListOwner = 33, "List-Owner", "list-owner";
    ListPost = 34, "List-Post", "list-post";
    ListSubscribe = 35, "List-Subscribe", "list-subscribe";
    ListUnsubscribe = 36, "List-Unsubscribe", "list-unsubscribe";
    ArcAuthenticationResults = 38, "ARC-Authentication-Results", "arc-authentication-results";
    ArcMessageSignature = 39, "ARC-Message-Signature", "arc-message-signature";
    ArcSeal = 40, "ARC-Seal", "arc-seal";
    DkimSignature = 41, "DKIM-Signature", "dkim-signature";
    Dkim2Signature = 42, "DKIM2-Signature", "dkim2-signature";
    MessageInstance = 43, "Message-Instance", "message-instance";
    AcceptLanguage = 44, "Accept-Language", "accept-language";
    AlternateRecipient = 45, "Alternate-Recipient", "alternate-recipient";
    ArchivedAt = 46, "Archived-At", "archived-at";
    AuthenticationResults = 47, "Authentication-Results", "authentication-results";
    AutoSubmitted = 48, "Auto-Submitted", "auto-submitted";
    Autoforwarded = 49, "Autoforwarded", "autoforwarded";
    Autosubmitted = 50, "Autosubmitted", "autosubmitted";
    ContentAlternative = 51, "Content-Alternative", "content-alternative";
    ContentDuration = 52, "Content-Duration", "content-duration";
    ContentFeatures = 53, "Content-features", "content-features";
    ContentMd5 = 54, "Content-MD5", "content-md5";
    ContentTranslationType = 55, "Content-Translation-Type", "content-translation-type";
    Conversion = 56, "Conversion", "conversion";
    ConversionWithLoss = 57, "Conversion-With-Loss", "conversion-with-loss";
    DlExpansionHistory = 58, "DL-Expansion-History", "dl-expansion-history";
    DeferredDelivery = 59, "Deferred-Delivery", "deferred-delivery";
    DeliveryDate = 60, "Delivery-Date", "delivery-date";
    DiscardedX400IpmsExtensions = 61, "Discarded-X400-IPMS-Extensions", "discarded-x400-ipms-extensions";
    DiscardedX400MtsExtensions = 62, "Discarded-X400-MTS-Extensions", "discarded-x400-mts-extensions";
    DiscloseRecipients = 63, "Disclose-Recipients", "disclose-recipients";
    DispositionNotificationOptions = 64, "Disposition-Notification-Options", "disposition-notification-options";
    DispositionNotificationTo = 65, "Disposition-Notification-To", "disposition-notification-to";
    DowngradedFinalRecipient = 66, "Downgraded-Final-Recipient", "downgraded-final-recipient";
    DowngradedInReplyTo = 67, "Downgraded-In-Reply-To", "downgraded-in-reply-to";
    DowngradedMessageId = 68, "Downgraded-Message-Id", "downgraded-message-id";
    DowngradedOriginalRecipient = 69, "Downgraded-Original-Recipient", "downgraded-original-recipient";
    DowngradedReferences = 70, "Downgraded-References", "downgraded-references";
    Encoding = 71, "Encoding", "encoding";
    Expires = 72, "Expires", "expires";
    GenerateDeliveryReport = 73, "Generate-Delivery-Report", "generate-delivery-report";
    HpOuter = 74, "HP-Outer", "hp-outer";
    Importance = 75, "Importance", "importance";
    IncompleteCopy = 76, "Incomplete-Copy", "incomplete-copy";
    Language = 77, "Language", "language";
    LatestDeliveryTime = 78, "Latest-Delivery-Time", "latest-delivery-time";
    ListUnsubscribePost = 79, "List-Unsubscribe-Post", "list-unsubscribe-post";
    MessageContext = 80, "Message-Context", "message-context";
    MessageType = 81, "Message-Type", "message-type";
    MmhsExemptedAddress = 82, "MMHS-Exempted-Address", "mmhs-exempted-address";
    MmhsExtendedAuthorisationInfo = 83, "MMHS-Extended-Authorisation-Info", "mmhs-extended-authorisation-info";
    MmhsSubjectIndicatorCodes = 84, "MMHS-Subject-Indicator-Codes", "mmhs-subject-indicator-codes";
    MmhsHandlingInstructions = 85, "MMHS-Handling-Instructions", "mmhs-handling-instructions";
    MmhsMessageInstructions = 86, "MMHS-Message-Instructions", "mmhs-message-instructions";
    MmhsCodressMessageIndicator = 87, "MMHS-Codress-Message-Indicator", "mmhs-codress-message-indicator";
    MmhsOriginatorReference = 88, "MMHS-Originator-Reference", "mmhs-originator-reference";
    MmhsPrimaryPrecedence = 89, "MMHS-Primary-Precedence", "mmhs-primary-precedence";
    MmhsCopyPrecedence = 90, "MMHS-Copy-Precedence", "mmhs-copy-precedence";
    MmhsMessageType = 91, "MMHS-Message-Type", "mmhs-message-type";
    MmhsOtherRecipientsIndicatorTo = 92, "MMHS-Other-Recipients-Indicator-To", "mmhs-other-recipients-indicator-to";
    MmhsOtherRecipientsIndicatorCc = 93, "MMHS-Other-Recipients-Indicator-CC", "mmhs-other-recipients-indicator-cc";
    MmhsAcp127MessageIdentifier = 94, "MMHS-Acp127-Message-Identifier", "mmhs-acp127-message-identifier";
    MmhsOriginatorPlad = 95, "MMHS-Originator-PLAD", "mmhs-originator-plad";
    MtPriority = 96, "MT-Priority", "mt-priority";
    Organization = 97, "Organization", "organization";
    OriginalEncodedInformationTypes = 98, "Original-Encoded-Information-Types", "original-encoded-information-types";
    OriginalFrom = 99, "Original-From", "original-from";
    OriginalMessageId = 100, "Original-Message-ID", "original-message-id";
    OriginalRecipient = 101, "Original-Recipient", "original-recipient";
    OriginatorReturnAddress = 102, "Originator-Return-Address", "originator-return-address";
    OriginalSubject = 103, "Original-Subject", "original-subject";
    PicsLabel = 104, "PICS-Label", "pics-label";
    PreventNonDeliveryReport = 105, "Prevent-NonDelivery-Report", "prevent-nondelivery-report";
    Priority = 106, "Priority", "priority";
    ReceivedSpf = 107, "Received-SPF", "received-spf";
    ReplyBy = 108, "Reply-By", "reply-by";
    RequireRecipientValidSince = 109, "Require-Recipient-Valid-Since", "require-recipient-valid-since";
    Sensitivity = 110, "Sensitivity", "sensitivity";
    Solicitation = 111, "Solicitation", "solicitation";
    Supersedes = 112, "Supersedes", "supersedes";
    TlsReportDomain = 113, "TLS-Report-Domain", "tls-report-domain";
    TlsReportSubmitter = 114, "TLS-Report-Submitter", "tls-report-submitter";
    TlsRequired = 115, "TLS-Required", "tls-required";
    VbrInfo = 116, "VBR-Info", "vbr-info";
    X400ContentIdentifier = 117, "X400-Content-Identifier", "x400-content-identifier";
    X400ContentReturn = 118, "X400-Content-Return", "x400-content-return";
    X400ContentType = 119, "X400-Content-Type", "x400-content-type";
    X400MtsIdentifier = 120, "X400-MTS-Identifier", "x400-mts-identifier";
    X400Originator = 121, "X400-Originator", "x400-originator";
    X400Received = 122, "X400-Received", "x400-received";
    X400Recipients = 123, "X400-Recipients", "x400-recipients";
    X400Trace = 124, "X400-Trace", "x400-trace";
    ApparentlyTo = 125, "Apparently-To", "apparently-to";
    Author = 126, "Author", "author";
    CfblAddress = 127, "CFBL-Address", "cfbl-address";
    CfblFeedbackId = 128, "CFBL-Feedback-ID", "cfbl-feedback-id";
    DeliveredTo = 129, "Delivered-To", "delivered-to";
    EdiintFeatures = 130, "EDIINT-Features", "ediint-features";
    EesstVersion = 131, "Eesst-Version", "eesst-version";
    ErrorsTo = 132, "Errors-To", "errors-to";
    Face = 133, "Face", "face";
    FormSub = 134, "Form-Sub", "form-sub";
    JabberId = 135, "Jabber-ID", "jabber-id";
    MmhsAuthorizingUsers = 136, "MMHS-Authorizing-Users", "mmhs-authorizing-users";
    Privicon = 137, "Privicon", "privicon";
    SioLabel = 138, "SIO-Label", "sio-label";
    SioLabelHistory = 139, "SIO-Label-History", "sio-label-history";
    WrongRecipient = 140, "Wrong-Recipient", "wrong-recipient";
}

/// Parsed header value.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum HeaderValue<'x> {
    /// Address list or group
    Address(Address<'x>),

    /// String
    Text(#[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::AsOwned))] Cow<'x, str>),

    /// List of strings
    TextList(
        #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
        Vec<Cow<'x, str>>,
    ),

    /// Datetime
    DateTime(DateTime),

    /// Content-Type or Content-Disposition header
    ContentType(ContentType<'x>),

    /// Received header
    Received(Box<Received<'x>>),

    #[default]
    Empty,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum Address<'x> {
    /// Address list
    List(Vec<Addr<'x>>),
    /// Group of addresses
    Group(Vec<Group<'x>>),
}

/// Header form
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum HeaderForm {
    Raw,
    Text,
    Addresses,
    GroupedAddresses,
    MessageIds,
    Date,
    URLs,
}
/// An RFC2047 Content-Type or RFC2183 Content-Disposition MIME header field.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct ContentType<'x> {
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::AsOwned))]
    pub c_type: Cow<'x, str>,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub c_subtype: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub attributes: Option<Vec<Attribute<'x>>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Attribute<'x> {
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::AsOwned))]
    pub name: Cow<'x, str>,
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::AsOwned))]
    pub value: Cow<'x, str>,
}

/// An RFC5322 datetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub tz_before_gmt: bool,
    pub tz_hour: u8,
    pub tz_minute: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub struct Received<'x> {
    #[cfg_attr(feature = "serde", serde(default))]
    pub from: Option<Host<'x>>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub from_ip: Option<IpAddr>,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub from_iprev: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub by: Option<Host<'x>>,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub for_: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub with: Option<Protocol>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub tls_version: Option<TlsVersion>,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub tls_cipher: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub id: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub ident: Option<Cow<'x, str>>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub helo: Option<Host<'x>>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub helo_cmd: Option<Greeting>,
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::Map<rkyv::with::AsOwned>))]
    pub via: Option<Cow<'x, str>>,
    pub date: Option<DateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum Host<'x> {
    Name(#[cfg_attr(feature = "rkyv", rkyv(with = rkyv::with::AsOwned))] Cow<'x, str>),
    IpAddr(IpAddr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum TlsVersion {
    SSLv2,
    SSLv3,
    TLSv1_0,
    TLSv1_1,
    TLSv1_2,
    TLSv1_3,
    DTLSv1_0,
    DTLSv1_2,
    DTLSv1_3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
pub enum Greeting {
    Helo,
    Ehlo,
    Lhlo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)
)]
#[allow(clippy::upper_case_acronyms)]
pub enum Protocol {
    // IANA Mail Transmission Types
    SMTP,
    ESMTP,
    ESMTPA,
    ESMTPS,
    ESMTPSA,
    LMTP,
    LMTPA,
    LMTPS,
    LMTPSA,
    MMS,
    UTF8SMTP,
    UTF8SMTPA,
    UTF8SMTPS,
    UTF8SMTPSA,
    UTF8LMTP,
    UTF8LMTPA,
    UTF8LMTPS,
    UTF8LMTPSA,

    // Non-Standard Mail Transmission Types
    HTTP,
    HTTPS,
    IMAP,
    POP3,
    Local, // includes stdin, socket, etc.
}

/// MIME Header field access trait
pub trait MimeHeaders<'x> {
    /// Returns the Content-Description field
    fn content_description(&self) -> Option<&str>;
    /// Returns the Content-Disposition field
    fn content_disposition(&self) -> Option<&ContentType<'_>>;
    /// Returns the Content-ID field
    fn content_id(&self) -> Option<&str>;
    /// Returns the Content-Encoding field
    fn content_transfer_encoding(&self) -> Option<&str>;
    /// Returns the Content-Type field
    fn content_type(&self) -> Option<&ContentType<'_>>;
    /// Returns the Content-Language field
    fn content_language(&self) -> &HeaderValue<'_>;
    /// Returns the Content-Location field
    fn content_location(&self) -> Option<&str>;
    /// Returns the attachment name, if any.
    fn attachment_name(&self) -> Option<&str> {
        self.content_disposition()
            .and_then(|cd| cd.attribute("filename"))
            .or_else(|| self.content_type().and_then(|ct| ct.attribute("name")))
    }
    // Returns true is the content type matches
    fn is_content_type(&self, type_: &str, subtype: &str) -> bool {
        self.content_type().is_some_and(|ct| {
            ct.c_type.eq_ignore_ascii_case(type_)
                && ct
                    .c_subtype
                    .as_ref()
                    .is_some_and(|st| st.eq_ignore_ascii_case(subtype))
        })
    }
}

pub trait GetHeader<'x> {
    fn header_value(&self, name: &HeaderName<'_>) -> Option<&HeaderValue<'x>>;
    fn header(&self, name: impl Into<HeaderName<'x>>) -> Option<&Header<'x>>;
}

struct BodyPartIterator<'x> {
    message: &'x Message<'x>,
    list: &'x [MessagePartId],
    pos: i32,
}

struct AttachmentIterator<'x> {
    message: &'x Message<'x>,
    pos: i32,
}
