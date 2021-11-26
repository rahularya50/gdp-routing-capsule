use crate::gdp::Gdp;
use crate::gdp::GdpAction;

use capsule::batch::GroupByBatchBuilder;
use capsule::packets::ip::v4::Ipv4;
use std::collections::HashMap;

pub type GdpGroupAction = Box<GroupByBatchBuilder<Gdp<Ipv4>>>;
pub type GdpMap<T> = HashMap<Option<T>, GdpGroupAction>;
pub type GdpPipeline = Box<dyn FnOnce(&mut GdpMap<GdpAction>)>;

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
    F: for<'a> FnOnce(&'a mut GdpMap<T>) -> (),
{
    f
}

#[macro_export]
macro_rules! pipeline {
    { $($key:expr => |$arg:tt| $body:block)+ } => {Box::new($crate::pipeline::constrain(move |lookup| {
        $crate::__move_compose!(lookup, $($key => |$arg| $body),*);
        lookup.insert(None, Box::new(|group| Box::new(group)));
    }))};
    { $($key:expr => |$arg:tt| $body:block)+ _ => |$_arg:tt| $_body:block } => {Box::new($crate::pipeline::constrain(move |lookup| {
        $crate::__move_compose!(lookup, $($key => |$arg| $body),*);
        lookup.insert(None, Box::new(|$_arg| Box::new($_body)));
    }))};
}
