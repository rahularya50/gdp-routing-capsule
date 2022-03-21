use std::collections::HashMap;

use capsule::batch::GroupByBatchBuilder;
use capsule::packets::ip::v4::Ipv4;
use capsule::packets::Packet;

use crate::gdp::{Gdp, GdpAction};

pub type GdpGroupAction<U> = Box<GroupByBatchBuilder<U>>;
pub type GdpMap<T, U> = HashMap<Option<T>, GdpGroupAction<U>>;
pub trait GdpPipeline<T: Packet>: FnOnce(&mut GdpMap<GdpAction, Gdp<T>>) {}

impl<T: FnOnce(&mut GdpMap<GdpAction, Gdp<U>>), U: Packet> GdpPipeline<U> for T {}

#[doc(hidden)]
#[macro_export]
macro_rules! __move_compose {
    ($map:ident, $($key:expr => |$arg:tt| $body:block),*) => {{
        $(
            $map.insert(Some($key), Box::new(move |$arg| Box::new($body)));
        )*
    }};
}

pub fn constrain<T, U, F>(f: F) -> F
where
    F: for<'a> FnOnce(&'a mut GdpMap<T, U>),
{
    f
}

#[macro_export]
macro_rules! pipeline {
    { $($key:expr => |$arg:tt| $body:block)+ } => {$crate::pipeline::constrain(move |lookup| {
        $crate::__move_compose!(lookup, $($key => |$arg| $body),*);
        lookup.insert(None, Box::new(|group| Box::new(group)));
    })};
    { $($key:expr => |$arg:tt| $body:block)+ _ => |$_arg:tt| $_body:block } => {$crate::pipeline::constrain(move |lookup| {
        $crate::__move_compose!(lookup, $($key => |$arg| $body),*);
        lookup.insert(None, Box::new(|$_arg| Box::new($_body)));
    })};
}
