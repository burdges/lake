

#[dervie(Debug, Clone, Copy, Default)]
pub struct ArrivalMetadata {
    pub data: [SURBMetadata; MAX_SURB_METADATA],
    pub count: u16,
}

impl ArrivalMetadata {
    /// 
    ///
    fn insert(&mut self, meta: SURBMetadata) {
        if self.count<MAX_SURB_METADATA {
            metadata[self.count] = delivery_surb.meta;
            self.count += 1; 
        } else {
            m = MAX_SURB_METADATA;
            for i in m/2 .. m { metadata[i-1] = metadata[i]; }
            metadata[m-1] = meta;
        }
    }
}


