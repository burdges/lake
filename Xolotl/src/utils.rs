
use std::ops::Deref;
use std::borrow::Borrow;
use std::convert::AsRef;

use std::sync;
use std::rc;


/// Reference counted pointer types
///
/// We do not implement a `downgrade` method becuase `Rc` and `Arc`
/// make `downgrade` not a method, so maybe people should specify the
/// type when downgrading for some reason.
///
trait RcClone<T> : Deref<Target=T> + Borrow<T> + AsRef<T> + Clone {
    // type Weak;
    // fn downgrade(&self) -> Weak;
}

impl<T> RcClone<T> for rc::Rc<T> { 
    // type Weak = rc::Weak<T>;
    // fn downgrade(&self) -> rc::Weak<T> { rc::Rc::downgrade(self) }
}
impl<T> RcClone<T> for sync::Arc<T> { 
    // type Weak = sync::Weak<T>;
    // fn downgrade(&self) -> sync::Weak<T> { rc::Arc::downgrade(self) }
}

/*

trait RcWeak<T> : Clone {
    type Strong;
    fn upgrade(&self) -> Option<Strong>
}

impl<T> RcWeak<T> for rc::Weak<T> {
    type Strong = rc::Rc<T>;
    fn upgrade(&self) -> Option<rc::Rc<T>> { rc::Weak::upgrade(self) }
}

impl<T> RcWeak<T> for snyc::Weak<T> {
    type Strong = sync::Arc<T>;
    fn upgrade(&self) -> Option<sync::Arc<T>> { sync::Weak::upgrade(self) }
}

*/
