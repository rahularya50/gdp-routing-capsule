use std::collections::HashMap;

use capsule::batch::GroupByBatchBuilder;
use capsule::packets::ip::v4::Ipv4;
use gdp_client::GdpAction;

use crate::dtls::DTls;
use crate::gdp::Gdp;

pub type GdpGroupAction<U> = Box<GroupByBatchBuilder<U>>;
pub type GdpMap<T> = HashMap<Option<T>, GdpGroupAction<Gdp<DTls<Ipv4>>>>;
pub trait GdpPipeline: FnOnce(&mut GdpMap<GdpAction>) {}

impl<T: FnOnce(&mut GdpMap<GdpAction>)> GdpPipeline for T {}

#[doc(hidden)]
#[macro_export]
macro_rules! __move_compose {
    ($map:ident, $($key:expr => |$arg:tt| $body:block),*) => {{
        $(
            $map.insert(Some($key), Box::new(move |$arg| Box::new($body)));
        )*
    }};
}

pub fn constrain<T, F>(f: F) -> F
where
    F: for<'a> FnOnce(&'a mut GdpMap<T>),
{
    f
}

#[macro_export]
macro_rules! pipeline {
    { $($key:expr => |$arg:tt| $body:block),+ $(,)? } => {$crate::pipeline::constrain(move |lookup| {
        $crate::__move_compose!(lookup, $($key => |$arg| $body),*);
        lookup.insert(None, Box::new(|group| Box::new(group)));
    })};
    { $($key:expr => |$arg:tt| $body:block),+ $(,)? _ => |$_arg:tt| $_body:block } => {$crate::pipeline::constrain(move |lookup| {
        $crate::__move_compose!(lookup, $($key => |$arg| $body),*);
        lookup.insert(None, Box::new(|$_arg| Box::new($_body)));
    })};
}
