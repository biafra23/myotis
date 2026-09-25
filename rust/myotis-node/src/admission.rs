//! Pure queue ownership. Cancelling queued work never releases an active slot.
use std::collections::{HashSet, VecDeque};

pub(crate) trait HasHandle {
    fn handle(&self) -> i64;
}

pub(crate) struct Admission<T> {
    queued: VecDeque<T>,
    active: HashSet<i64>,
}

impl<T: HasHandle> Admission<T> {
    pub fn new() -> Self {
        Self {
            queued: VecDeque::new(),
            active: HashSet::new(),
        }
    }
    pub fn push(&mut self, job: T) {
        self.queued.push_back(job);
    }
    pub fn take_ready(&mut self) -> Option<T> {
        let index = self
            .queued
            .iter()
            .position(|job| !self.active.contains(&job.handle()))?;
        let job = self.queued.remove(index)?;
        self.active.insert(job.handle());
        Some(job)
    }
    pub fn finish(&mut self, handle: i64) {
        self.active.remove(&handle);
    }
    pub fn is_active(&self, handle: i64) -> bool {
        self.active.contains(&handle)
    }
    pub fn cancel_queued(&mut self, handle: Option<i64>) -> Vec<T> {
        let mut cancelled = Vec::new();
        let mut index = 0;
        while index < self.queued.len() {
            if handle.is_none_or(|h| self.queued[index].handle() == h) {
                if let Some(job) = self.queued.remove(index) {
                    cancelled.push(job);
                }
            } else {
                index += 1;
            }
        }
        cancelled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug, PartialEq)]
    struct Job(i64, u32);
    impl HasHandle for Job {
        fn handle(&self) -> i64 {
            self.0
        }
    }

    #[test]
    fn queued_target_cancels_with_both_workers_owned_by_other_chains() {
        let mut queue = Admission::new();
        queue.push(Job(1, 1));
        queue.push(Job(2, 2));
        assert_eq!(queue.take_ready(), Some(Job(1, 1)));
        assert_eq!(queue.take_ready(), Some(Job(2, 2)));
        queue.push(Job(3, 3));
        queue.push(Job(3, 4));
        // No worker completion is needed to return ownership of target jobs.
        assert_eq!(queue.cancel_queued(Some(3)), vec![Job(3, 3), Job(3, 4)]);
        assert!(!queue.is_active(3));
        assert!(queue.is_active(1));
        assert!(queue.is_active(2));
        assert!(queue.take_ready().is_none());
    }

    #[test]
    fn cancelling_queued_sibling_does_not_release_actual_active_owner() {
        let mut queue = Admission::new();
        queue.push(Job(1, 1));
        assert_eq!(queue.take_ready(), Some(Job(1, 1)));
        queue.push(Job(1, 2));
        assert_eq!(queue.cancel_queued(Some(1)), vec![Job(1, 2)]);
        assert!(queue.is_active(1));
        queue.push(Job(1, 3));
        assert!(queue.take_ready().is_none());
        queue.finish(1);
        assert_eq!(queue.take_ready(), Some(Job(1, 3)));
    }
}
