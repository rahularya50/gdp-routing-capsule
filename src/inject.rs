use anyhow::Result;
use capsule::batch::Batch;
use capsule::batch::Disposition;

#[allow(missing_debug_implementations)]
pub struct Inject<B: Batch, F>
where
    F: FnMut(&B::Item) -> Result<B::Item>,
{
    batch: B,
    f: F,
    slot: Option<B::Item>,
}

impl<B: Batch, F> Inject<B, F>
where
    F: FnMut(&B::Item) -> Result<B::Item>,
{
    #[inline]
    pub fn new(batch: B, f: F) -> Self {
        Inject {
            batch,
            f,
            slot: None,
        }
    }
}

impl<B: Batch, F> Batch for Inject<B, F>
where
    F: FnMut(&B::Item) -> Result<B::Item>,
{
    type Item = B::Item;

    #[inline]
    fn replenish(&mut self) {
        self.batch.replenish();
    }

    #[inline]
    fn next(&mut self) -> Option<Disposition<B::Item>> {
        if let Some(pkt) = self.slot.take() {
            Some(Disposition::Act(pkt))
        } else {
            self.batch.next().map(|disp| match disp {
                Disposition::Act(packet) => (self.f)(&packet).map_or_else(
                    |e| Disposition::Abort(e),
                    |new| {
                        self.slot.replace(new);
                        Disposition::Act(packet)
                    },
                ),
                Disposition::Emit => Disposition::Emit,
                Disposition::Drop(mbuf) => Disposition::Drop(mbuf),
                Disposition::Abort(err) => Disposition::Abort(err),
            })
        }
    }
}
