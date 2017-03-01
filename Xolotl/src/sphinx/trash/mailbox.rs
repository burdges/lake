






    fn make_queue<I>(&self, k: &K, new_packets: I) -> PM
      where I: IntoIterator<Item=(PacketName,PM::Packet)>
    {
        let pm = PM::new_unfamiliar(self.0);
        let packets = pm.packets().write().unwrap();  // Owned here
        for (k,v) in new_packets { packets.insert(k,v); }
        pm
    }
    fn enqueue_familiar<I>(&self, k: &K, new_packets: I) -> Option<PM>
      where I: IntoIterator<Item=(PacketName,PM::Packet)>
    {
        let queues = self.1.read().unwrap(); // PoisonError 
        let queue = if let Some(q) = queues.get(k) { q } else {
            return Ok(Some( self.make_queue(k, new_packets ) ));
        };

        let packets = match queue.packets().write() { Ok(p) => p, Err(e) => {
            let itr = e.into_inner().drain().chain( &[(packet_name,packet)] );
            return Ok(Some( self.new_queue(k,itr) ));
        } };

        if let Some(old) = packets.insert(*packet_name,packet) {
            // TODO Improve this error somehow?  Either replay protection failed,
            // or else the hash itself function is broken, or else ??
            Err( SphinxError::InternalError("Packet name collision detected!") )
        } else { Ok(None) } 
    }

// &[(packet_name,packet)]
    pub fn enqueue_one<I>(&self, k: &K, new_packets: I)
      where I: IntoIterator<Item=(PacketName,PM::Packet)>
      -> SphinxResult<()> {
        match self.enqueue_familiar(k, new_packets) {
            Ok(None) => return ??,
            Ok(Some(pm)) => {
                
            },
        }

        let pm = PM::new_unfamiliar(self.0);
        {
            let packets = pm.packets().write().unwrap();  // Owned here
            packets.insert(*packet_name,packet).unwrap();  // Empty 
        }
        let queues = self.1.write() ?; // PoisonError
        queues.insert(*k, pm );
        Ok(())
    }
















I kinda found answers to my questions about poisoned locks.  There are three approaches :
 (1) call unwrap() to panic the thread  https://internals.rust-lang.org/t/mutex-locking-and-poisoning/2019
 (2) ignore the error with mutex.lock().unwrap_or_else(|e| e.into_inner())  YOLO   https://github.com/rust-lang/rust/issues/35092  
 (3) repair something because you think you know what happened

A good first approach is (1) and jusst write your code so that it cannot panic in locks, and fix any that happen.  If that fails, then maybe try another appraoch.



















    fn enqueue_new(&self, k: &K, packet_name: &PacketName, packet: PM::Packet) -> PM {
        let pm = PM::new_unfamiliar(self.0);
        let packets = pm.packets().write().unwrap();  // Owned here
        packets.insert(*packet_name,packet);
    }
    fn enqueue_familiar(&self, k: &K, packet_name: &PacketName, packet: PM::Packet)
      -> Result<Option<PM>,()> {
        let queues = self.1.read().unwrap_or_else( |e| { e.into_inner() } ); // PoisonError
        let queue = if let Some(q) = queues.get(k) { q } else {
            return Ok( Some() );
        };

        let packets = match queue.packets().write() { Ok(p) => p, Err(e) => {
            let pm = PM::new_unfamiliar(self.0);
            let packets = pm.packets().write().unwrap();  // Owned here
            replace_pm = Some( e.into_inner().drain().collect() );
            packets.insert(*packet_name,packet);
            return Ok( Some(pm) );
        } };

        if let Some(old) = packets.insert(*packet_name,packet) {
            // TODO Improve this error somehow?  Either replay protection failed,
            // or else the hash itself function is broken, or else ??
            Err( SphinxError::InternalError("Packet name collision detected!") )
        } else { Ok(true) } 
    }

    pub fn enqueue(&self, k: &K, packet_name: &PacketName, packet: PM::Packet)
      -> SphinxResult<()> {
        let mut replace = None;
        if self.enqueue_familiar(k,packet_name,packet) ? { return Ok(()); }

        let pm = PM::new_unfamiliar(self.0);
        {
            let packets = pm.packets().write().unwrap();  // Owned here
            packets.insert(*packet_name,packet).unwrap();  // Empty 
        }
        let queues = self.1.write() ?; // PoisonError
        queues.insert(*k, pm );
        Ok(())
    }


