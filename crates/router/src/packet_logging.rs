use std::net::Ipv4Addr;

use capsule::batch::{Batch, Disposition};
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::{Packet, Udp};

use crate::dtls::DTls;
use crate::gdp::Gdp;

pub trait LogArrive: Batch + Sized {
    type OutBatch: Batch;
    fn logarrive(self, name: &'static str, details: &'static str, debug: bool) -> Self::OutBatch;
}

pub trait LogFail: Batch + Sized {
    type OutBatch: Batch;
    fn logfail(self, name: &'static str, details: &'static str, debug: bool) -> Self::OutBatch;
}

pub trait HasSrcDest {
    fn src(&self) -> Ipv4Addr;
    fn dst(&self) -> Ipv4Addr;
}

impl HasSrcDest for DTls<Ipv4> {
    fn src(&self) -> Ipv4Addr {
        return self.envelope().envelope().src();
    }

    fn dst(&self) -> Ipv4Addr {
        return self.envelope().envelope().src();
    }
}

impl HasSrcDest for Udp<Ipv4> {
    fn src(&self) -> Ipv4Addr {
        return self.envelope().src();
    }

    fn dst(&self) -> Ipv4Addr {
        return self.envelope().src();
    }
}

impl<T: Batch<Item = Gdp<U>> + Sized, U> LogArrive for T
where
    U: Packet + HasSrcDest,
{
    type OutBatch = impl Batch<Item = Self::Item>;

    fn logarrive(self, name: &'static str, details: &'static str, debug: bool) -> Self::OutBatch {
        self.for_each(move |packet| {
            if debug {
                println!(
                    "handling packet in {} ({}) : src: {:?}, dst: {:?}, type: {:?}",
                    name,
                    details,
                    packet.src(),
                    packet.dst(),
                    packet.action()?
                );
            }
            Ok(())
        })
    }
}

impl<T: Batch + Sized> LogFail for T {
    type OutBatch = impl Batch;

    fn logfail(self, name: &'static str, details: &'static str, debug: bool) -> Self::OutBatch {
        self.inspect(move |disp| {
            if debug {
                if let Disposition::Abort(err) = disp {
                    println!(
                        "Packet aborted by {} ({}) with error {}",
                        name, details, err
                    );
                }
            }
        })
    }
}
