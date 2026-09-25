//! Ownership for the peer pool's parent loops and their spawned network jobs.
use std::future::Future;
use std::sync::Mutex;
use tokio::task::JoinHandle;

#[derive(Default)]
pub(super) struct Tasks(Mutex<(bool, Vec<JoinHandle<()>>)>);
impl Tasks {
    pub fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if tasks.0 {
            return;
        }
        tasks.1.retain(|task| !task.is_finished());
        tasks.1.push(tokio::spawn(future));
    }

    fn take(&self) -> Vec<JoinHandle<()>> {
        let mut tasks = self.0.lock().unwrap_or_else(|e| e.into_inner());
        tasks.0 = true;
        for task in &tasks.1 {
            task.abort();
        }
        std::mem::take(&mut tasks.1)
    }

    pub async fn stop(&self) {
        for task in self.take() {
            let _ = task.await;
        }
    }
    pub fn abort(&self) {
        drop(self.take());
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        self.abort();
    }
}
