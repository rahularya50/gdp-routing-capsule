#[doc(hidden)]
#[macro_export]
macro_rules! __move_compose {
    ($map:ident, $($key:expr => |$arg:tt| $body:block),*) => {{
        $(
            $map.insert(Some($key), Box::new(move |$arg| Box::new($body)));
        )*
    }};
}

#[macro_export]
macro_rules! move_compose {
    ($map:ident { $($key:expr => |$arg:tt| $body:block)+ }) => {{
        $crate::__move_compose!($map, $($key => |$arg| $body),*);
        $map.insert(None, Box::new(|group| Box::new(group)));
    }};
    ($map:ident { $($key:expr => |$arg:tt| $body:block)+ _ => |$_arg:tt| $_body:block }) => {{
        $crate::__move_compose!($map, $($key => |$arg| $body),*);
        $map.insert(None, Box::new(|$_arg| Box::new($_body)));
    }};
    ($map:ident { $($key:expr),+ => |$arg:tt| $body:block }) => {{
        $crate::__move_compose!($map { $($key => |$arg| $body)+ });
    }};
    ($map:ident { $($key:expr),+ => |$arg:tt| $body:block _ => |$_arg:tt| $_body:block }) => {{
        $crate::__move_compose!($map { $($key => |$arg| $body)+ _ => |$_arg| $_body });
    }};
    ($map:ident { _ => |$_arg:tt| $_body:block }) => {{
        $map.insert(None, Box::new(|$_arg| Box::new($_body)));
    }};
}
