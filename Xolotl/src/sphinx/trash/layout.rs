


/// Sphinx paramaters
///
/// We require a `&'static SphinxParams` when used because the
/// protocol specification should be compiled into the binary.
///
/// In some cases, there could be minor performance hits if some
/// of these are not multiples of the ChaCha blocksize of 64 byte.
pub trait Params {
    /// Unique version identifier for the protocol
    const protocol_name: &'static str;

    /// Length of the routing information block `Beta`.
    const beta_length: Length;

    /// Maximal amount of routing infomrmation in `Beta` consued
    /// by a single sub-hop.
    const max_beta_tail_length: Length;

    /// Maximum length of the SURB.  At most half of `beta_length - 48`.
    ///
    /// Alpha and Gamma are encoded into the "bottom" of beta, and
    /// hence do not contribute here.  This is unlikely to change.
    /// As a result this should not exceed `beta_length`
    const max_surb_beta_length: Length;

    /// Length of the SURB log.
    const surb_log_length: Length;

    /// Approved message body lengths
    const body_lengths: &'static [Length];

    /// Sphinx header length
    #[inline(always)]
    fn header_length(&self) -> usize {
        ALPHA_LENGTH + GAMMA_LENGTH
        + Self::beta_length as usize
        + Self::surb_log_length as usize
    }
}









/// Sphinx `'static` runtime paramaters 
///
/// We require a `&'static SphinxParams` when used because the
/// protocol specification should be compiled into the binary.
///
/// In some cases, there could be minor performance hits if some
/// of these are not multiples of the ChaCha blocksize of 64 byte.
#[derive(Debug)] // Clone, Copy
pub struct SphinxParams {
    /// Unique version identifier for the protocol
    pub PROTOCOL_NAME: &'static str,

    /// Length of the routing information block `Beta`.
    pub BETA_LENGTH: Length,

    /// Maximal amount of routing infomrmation in `Beta` consued
    /// by a single sub-hop.
    pub MAX_BETA_TAIL_LENGTH: Length,

    /// Maximum length of the SURB.  At most half of `BETA_LENGTH - 48`.
    ///
    /// Alpha and Gamma are encoded into the "bottom" of beta, and
    /// hence do not contribute here.  This is unlikely to change.
    /// As a result this should not exceed `BETA_LENGTH`
    pub MAX_SURB_BETA_LENGTH: Length,

    /// Length of the SURB log.
    pub SURB_LOG_LENGTH: Length,

    pub DELAY_LAMBDA: f64,

    /// Approved message body lengths
    pub BODY_LENGTHS: &'static [Length],
}










    /// Copy the SURB to beta, zeroing the tail of beta if beta is 
    /// is longer.  Zeroing the tail of beta is safe because this
    /// only gets called during cross over and the new beta gets
    /// encrypted.  If this assuption changes, then we must fill 
    /// beta using a new stream cipher.  We must fill beta with data
    /// known by the SURB creator regardless, like zeros.
    pub fn copy_surb_to_beta(&mut self) {
        // Avoid these debug_asserts with HideMut above?
        debug_assert_eq!(self.surb.len(),self.params.surb_length);
        debug_assert_eq!(self.beta.len(),self.params.beta_length);
        let l = ::std::cmp::min(self.surb.len(),self.beta.len());
        self.beta[..l].copy_from_slice(self.surb);
        for i in self.beta[l..].iter_mut() { *i = 0; }
    }



