// Copyright 2016 Jeffrey Burdges.

//! Sphinx node mailbox routines


pub const MAILBOX_NAME_LENGTH : usize = 16;
pub type MailboxNameBytes = [u8; MAILBOX_NAME_LENGTH];

/// Identifier for a mailbox where we store messages to be
/// picked up latr.
#[derive(Debug, Copy, Clone, Default)]
pub struct MailboxName(pub MailboxNameBytes);



