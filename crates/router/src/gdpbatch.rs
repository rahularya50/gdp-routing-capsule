use anyhow::Result;
use capsule::batch::Batch;

use crate::inject::Inject;

pub trait GdpBatch: Batch {
    fn inject<F>(self, f: F) -> Inject<Self, F>
    where
        F: FnMut(&Self::Item) -> Result<Self::Item>,
        Self: Sized,
    {
        Inject::new(self, f)
    }
}

impl<T: Batch> GdpBatch for T {}
