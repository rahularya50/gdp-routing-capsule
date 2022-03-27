use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use capsule::batch::Pipeline;
use pin_project::pin_project;

#[pin_project]
pub struct Schedule<'a, T: Future<Output = ()>> {
    name: &'a str,
    #[pin]
    future: T,
}

impl<T: Future<Output = ()>> Schedule<'_, T> {
    pub fn new(name: &str, future: T) -> Schedule<T> {
        Schedule { name, future }
    }
}

impl<T: Future<Output = ()>> Pipeline for Schedule<'_, T> {
    fn name(&self) -> &str {
        self.name
    }

    fn run_once(&mut self) {
        unimplemented!();
    }
}

impl<T: Future<Output = ()>> Future for Schedule<'_, T> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().future.as_mut().poll(cx)
    }
}
