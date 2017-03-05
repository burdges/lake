
use std::sync;
use std::rc;


/// Reference counted pointer types
///
///
trait RcClone<T> : Deref<Target=T> + Borrow<T> + AsRef<T> + Clone {
    type Weak;
    fn downgrade(&self) -> Weak<T>;
}

impl<T> RcClone<T> for Rc<T> { 
    type Weak = rc::Weak;
    fn downgrade(&self) -> Weak<T> { rc::Rc::downgrade(self) }
}
impl<T> RcClone<T> for Arc<T> { 
    type Weak = sync::Weak;
    fn downgrade(&self) -> Weak<T> { rc::Arc::downgrade(self) }
}

