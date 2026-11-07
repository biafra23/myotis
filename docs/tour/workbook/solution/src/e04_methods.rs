//! Exercise 4: methods and receivers (`&self`, `&mut self`, `self`).
//! Modelled on `EnrSeq` in roost/src/enr.rs and `SyncHandle::stop(self)`.

/// A strictly increasing sequence number that remembers what it did.
pub struct Counter {
    current: u64,
    log: Vec<String>,
}

impl Counter {
    /// Associated function (no `self`): a new counter starting at 1.
    pub fn start() -> Counter {
        //@begin
        Counter { current: 1, log: Vec::new() }
        //@end
    }

    /// Shared borrow: read only.
    pub fn current(&self) -> u64 {
        //@begin
        self.current
        //@end
    }

    /// Exclusive borrow: advance by one and log "bump to N".
    /// `Err("overflow")` instead of wrapping when already at `u64::MAX`.
    pub fn bump(&mut self) -> Result<u64, String> {
        //@begin
        let next = self.current.checked_add(1).ok_or_else(|| "overflow".to_string())?;
        self.current = next;
        self.log.push(format!("bump to {next}"));
        Ok(next)
        //@end
    }

    /// By value: consumes the counter and hands its log to the caller.
    /// After `finish`, the counter can no longer be used (the compiler checks).
    pub fn finish(self) -> Vec<String> {
        //@begin
        self.log
        //@end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receivers() {
        let mut c = Counter::start();
        assert_eq!(c.bump(), Ok(2));
        assert_eq!(Counter::bump(&mut c), Ok(3), "the dot is sugar for this");
        assert_eq!(c.current(), 3);
        let log = c.finish();
        assert_eq!(log, vec!["bump to 2".to_string(), "bump to 3".to_string()]);
        // c.current();  // <- uncomment: "borrow of moved value: `c`"
    }

    #[test]
    fn methods_are_functions() {
        let maybe: Option<Counter> = Some(Counter::start());
        // A method passed where a function is expected, as roost does with
        // `enr_seq.as_ref().map(EnrSeq::current)`.
        assert_eq!(maybe.as_ref().map(Counter::current), Some(1));
    }

    #[test]
    fn overflow_is_an_error() {
        let mut c = Counter { current: u64::MAX, log: Vec::new() };
        assert_eq!(c.bump(), Err("overflow".to_string()));
        assert_eq!(c.current(), u64::MAX);
    }
}
