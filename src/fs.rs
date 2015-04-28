// Copyright (C) 2015 Mickaël Salaün
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

use collections::{Bound, BTreeSet};
use collections::btree_set::Range;
use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use super::{Action, Access, VecAccess, SetAccess, vec2opt};

// Test
#[allow(unused_imports)]
use std::env;

/// Greedy access control
///
/// Remove sub-restrictions:
/// > /foo(rw) + /foo/bar(ro) => /foo(rw)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileAccess {
    pub path: Rc<PathBuf>,
    pub action: Action,
}

macro_rules! new_access {
    ($name: ident, $($action: expr)+) => {
        pub fn $name(path: PathBuf) -> Result<Vec<FileAccess>, ()> {
            let path = Rc::new(path);
            let ret = vec!($(FileAccess::new(path.clone(), $action)),+);
            let len = ret.len();
            let ret: Vec<_> = ret.into_iter().filter_map(|x| x.ok()).collect();
            if len == ret.len() {
                Ok(ret)
            } else {
                Err(())
            }
        }
    }
}

impl AsRef<Path> for FileAccess {
    fn as_ref(&self) -> &Path {
        self.path.as_ref()
    }
}

#[allow(dead_code)]
impl FileAccess {
    new_access!(new_ro, Action::Read);
    new_access!(new_rw, Action::Read Action::Write);
    new_access!(new_wo, Action::Write);

    pub fn new(path: Rc<PathBuf>, action: Action) -> Result<Self, ()> {
        // Enforce absolute path
        if !path.is_absolute() {
            return Err(());
        }
        Ok(FileAccess {
            path: path,
            action: action,
        })
    }

    pub fn contains(&self, other: &Self) -> bool {
        self.action == other.action && other.as_ref().starts_with(self)
    }

    fn _greedy_ord(greedy: bool, a: &FileAccess, b: &FileAccess) -> Ordering {
        match a.action.cmp(&b.action) {
            Ordering::Equal => {
                let ord = a.path.cmp(&b.path);
                if greedy {
                    ord
                } else {
                    ord.reverse()
                }
            }
            ord => ord,
        }
    }
}

impl PartialOrd for FileAccess {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.action.partial_cmp(&other.action) {
            Some(Ordering::Equal) => match self.path.partial_cmp(&other.path) {
                Some(ord) => Some(ord.reverse()),
                pord => pord,
            },
            pord => pord,
        }
    }
}

/// Ordering to set the more accurate (path) access right first
impl Ord for FileAccess {
    fn cmp(&self, other: &Self) -> Ordering {
        FileAccess::_greedy_ord(false, self, other)
    }
}

impl Access for Rc<FileAccess> {
    fn new_intersect(&self, access: Self) -> Option<Self> {
        // Avoid duplicate ressources
        if *self == access {
            return Some(self.clone());
        }
        if self.contains(&*access) {
            return Some(access);
        }
        None
    }

    // Assume there is no duplicates in `other`
    fn new_intersect_all(&self, other: Vec<Self>) -> Option<Vec<Self>> {
        // TODO: Uniquify vec!(self).append(other_access)
        vec2opt(other.into_iter().filter_map(|x| self.new_intersect(x)).collect())
    }
}

impl VecAccess for Vec<Rc<FileAccess>> {
    fn uniquify(mut self) -> Self {
        // Greedy sort to remove useless nested access
        self.sort_by(|a, b| { FileAccess::_greedy_ord(true, a, b) });

        // Remove useless elements
        let mut prev: Option<Rc<FileAccess>> = None;
        self.into_iter().filter_map(
            |curr| {
                if let Some(ref p) = prev {
                    if p.contains(&curr) {
                        return None;
                    }
                }
                prev = Some(curr.clone());
                Some(curr)
            }).collect()
        // No need to sort because it will be integrated in a BTree
    }
}

// TODO: Split FileAccess into a read set and a write set?
impl SetAccess for BTreeSet<Rc<FileAccess>> {
    fn is_allowed(&self, access: &Rc<FileAccess>) -> bool {
        match self.range(Bound::Included(access), Bound::Unbounded).next() {
            Some(x) => x.contains(access),
            None => false,
        }
    }

    fn range_read<'a>(&'a self) -> Range<'a, Rc<FileAccess>> {
        // The root is absolute, no possible error
        let read_root = Rc::new(FileAccess::new(Rc::new(PathBuf::from("/")), Action::Read).unwrap());
        self.range(Bound::Unbounded, Bound::Included(&read_root))
    }

    fn range_write<'a>(&'a self) -> Range<'a, Rc<FileAccess>> {
        // The root is absolute, no possible error
        let read_root = Rc::new(FileAccess::new(Rc::new(PathBuf::from("/")), Action::Read).unwrap());
        self.range(Bound::Excluded(&read_root), Bound::Unbounded)
    }
}


pub fn new_path<T>(path: T) -> PathBuf where T: AsRef<Path> {
    let path = path.as_ref();
    if path.is_absolute() {
        path.into()
    } else {
        let cwd = match env::current_dir() {
            Ok(d) => d,
            Err(e) => panic!("Fail to get current working directory: {}", e),
        };
        cwd.join(path)
    }
}

#[macro_export]
macro_rules! new_acl {
    ($($new: ident $path: expr),+) => {
        vec!($(FileAccess::$new(new_path($path)).unwrap()),+).into_iter().
            flat_map(|x| x.into_iter()).map(|x| Rc::new(x)).collect::<Vec<_>>()
    }
}

#[macro_export]
macro_rules! let_dom {
    ($pool: ident, $name: ident, $acl: expr) => {
        let $name = $pool.new_dom(stringify!($name).to_string(), $acl)
    }
}

#[cfg(test)]
mod tests {
    use {Access, Action, Domain, DomainKind, FileAccess, RcDomain, ResPool, SetAccess};
    use {new_path, vec2opt};
    use collections::BTreeSet;
    use std::path::PathBuf;
    use std::rc::Rc;

    #[test]
    fn acces_range() {
        let mut pool = ResPool::new();
        let acl_read = new_acl!(
            new_ro "/usr",
            new_ro "/tmp",
            new_ro "/opt",
            new_ro "/home/x",
            new_ro "/home/doc"
        );
        let acl_write = new_acl!(
            new_wo "/tmp",
            new_wo "/home/x"
        );
        let acl_all = new_acl!(
            new_ro "/home/doc",
            new_rw "/home/x",
            new_ro "/opt",
            new_ro "/usr",
            new_rw "/tmp"
        );
        let_dom!(pool, dom1, acl_all);
        let range_read: Vec<_> = dom1.acl.range_read().map(|x| x.clone()).collect();
        assert_eq!(acl_read, range_read);
        let range_write: Vec<_> = dom1.acl.range_write().map(|x| x.clone()).collect();
        assert_eq!(acl_write, range_write);
    }

    #[test]
    fn dom_allow1() {
        let mut pool = ResPool::new();
        let dom1_acl = new_acl!(new_ro "/foo");
        let_dom!(pool, dom1, dom1_acl.clone());

        let dom2_acl = new_acl!(new_rw "/foo/bar");
        let_dom!(pool, dom2, dom2_acl.clone());

        let fa1 = Rc::new(FileAccess::new(Rc::new(PathBuf::from("/foo/bar")), Action::Read).unwrap());
        let dom1_acl_inter = vec2opt(dom1_acl.iter().
                                      filter_map(|x| x.new_intersect_all(dom2_acl.clone())).
                                      flat_map(|x| x.into_iter()).collect());
        assert_eq!(dom1_acl_inter, Some(vec!(fa1.clone())));
        assert_eq!(dom1.allow(&dom2_acl), Some(vec!(fa1.clone())));

        let dom2_acl_inter = vec2opt(dom2_acl.iter().
                                      filter_map(|x| x.new_intersect_all(dom1_acl.clone())).
                                      flat_map(|x| x.into_iter()).collect());
        assert_eq!(dom2_acl_inter, None);
        assert_eq!(dom2.allow(&dom1_acl), None);

        let dom0_raw = dom1.new_intersect(&dom2).unwrap();
        let check_acl_inter = set!(fa1.clone());
        assert_eq!(dom0_raw.acl, check_acl_inter);
    }

    #[test]
    fn dom_allow2() {
        let mut pool = ResPool::new();
        let_dom!(pool, dom1, new_acl!(new_rw "/foo"));
        let_dom!(pool, dom2, new_acl!(new_rw "/foo/bar"));

        let bar_path = Rc::new(PathBuf::from("/foo/bar"));
        let fa1 = set!(
            Rc::new(FileAccess::new(bar_path.clone(), Action::Read).unwrap()),
            Rc::new(FileAccess::new(bar_path.clone(), Action::Write).unwrap())
            );

        let dom0_raw = dom1.new_intersect(&dom2).unwrap();
        assert_eq!(dom0_raw.acl, fa1.clone());
    }

    #[test]
    fn dom_allow3() {
        let dom1_acl = new_acl!(new_rw "/foo");

        let mut pool = ResPool::new();
        let_dom!(pool, dom2, new_acl!(
            new_ro "/",
            new_rw "/foo"
        ));

        // The domain must return the more accurate access right: Read + Write
        assert_eq!(dom2.allow(&dom1_acl), Some(dom1_acl));
    }

    #[test]
    fn dom_intersect1() {
        let mut pool = ResPool::new();
        let_dom!(pool, dom1, new_acl!(
            new_ro "/home/doc",
            new_rw "/home/x",
            new_ro "/opt",
            new_ro "/usr",
            new_rw "/tmp"
        ));
        let_dom!(pool, dom2, new_acl!(
            new_rw "/home/doc/foo",
            new_ro "/home",
            new_ro "/usr",
            new_rw "/tmp"
        ));

        let check_acl_inter: BTreeSet<_> = new_acl!(
            new_ro "/usr",
            new_ro "/tmp",
            new_ro "/home/x",
            new_ro "/home/doc",
            new_wo "/tmp"
        ).into_iter().collect();
        let check_dom_inter = Domain::new("check_inter".to_string(), DomainKind::Intersection,
                                          check_acl_inter.clone(), BTreeSet::new());

        let dom0_raw = dom1.new_intersect(&dom2).unwrap();
        assert_eq!(dom0_raw.acl, check_dom_inter.acl);

        // Check without element reduction (uniquify)
        assert_eq!(dom0_raw.acl, check_acl_inter);
    }

    #[test]
    fn dom_intersect2() {
        let mut pool = ResPool::new();
        let_dom!(pool, dom1, new_acl!(
            new_ro "/home/doc",
            new_rw "/home/x"
        ));
        let_dom!(pool, dom2, new_acl!(
            new_ro "/home/z"
        ));

        // No intersection
        let dom0_raw = dom1.new_intersect(&dom2);
        assert_eq!(dom0_raw, None);
    }

    // TODO: Check resource's domains (e.g. intersection)

    #[test]
    fn pool_allow1() {
        let mut pool = ResPool::new();
        let_dom!(pool, dom1, new_acl!(
            new_ro "/home/doc",
            new_rw "/home/x",
            new_rw "/home/z",
            new_ro "/usr",
            new_rw "/tmp"
        ));
        let_dom!(pool, dom2, new_acl!(
            new_rw "/home/doc/foo",
            new_ro "/home",
            new_ro "/home/z",
            new_ro "/usr",
            new_rw "/tmp"
        ));

        let dom0_raw = dom1.new_intersect(&dom2).unwrap();

        let want = new_acl!(new_rw "/home/doc/foo");
        assert_eq!(pool.allow(&want), Some(dom2.clone()));

        let want = new_acl!(new_rw "/home/doc/foo/bar");
        assert_eq!(pool.allow(&want), Some(dom2.clone()));

        let want = new_acl!(new_rw "/home/doc");
        assert_eq!(pool.allow(&want), None);

        let want = new_acl!(new_ro "/home/doc");
        assert_eq!(pool.allow(&want), Some(dom0_raw.clone()));

        let want = new_acl!(new_ro "/home/doc");
        assert_eq!(pool.allow(&want), Some(dom0_raw.clone()));

        let want = new_acl!(new_rw "/home");
        assert_eq!(pool.allow(&want), None);

        let want = new_acl!(new_ro "/home");
        assert_eq!(pool.allow(&want), Some(dom2.clone()));

        let want = new_acl!(new_rw "/tmp/a/b");
        assert_eq!(pool.allow(&want), Some(dom0_raw.clone()));
    }

    #[test]
    #[allow(unused_variables)]
    fn pool_match1() {
        let mut pool = ResPool::new();
        let_dom!(pool, dom1, new_acl!(
            new_rw "/"
        ));
        let_dom!(pool, dom2, new_acl!(
            new_rw "/a"
        ));
        let_dom!(pool, dom3, new_acl!(
            new_rw "/a/b/c",
            new_rw "/a/d"
        ));
        let_dom!(pool, dom4, new_acl!(
            new_rw "/a/e"
        ));
        let want = new_acl!(new_rw "/a/e/x");
        let dom_check = dom1.new_intersect_all(&vec!(&dom2, &dom4)).unwrap();
        assert_eq!(pool.allow(&want), Some(dom_check));
    }

    #[test]
    fn pool_equivalent1() {
        let mut pool = ResPool::new();
        let_dom!(pool, dom1, new_acl!(
            new_ro "/a",
            new_rw "/b"
        ));
        let_dom!(pool, dom2, new_acl!(
            new_ro "/a",
            new_rw "/b",
            new_rw "/c"
        ));

        let dom0_raw = dom1.new_intersect(&dom2).unwrap();

        assert_eq!(&dom1, &dom0_raw);

        let want = new_acl!(new_rw "/b/x");
        assert_eq!(pool.allow(&want), Some(dom1.clone()));
        assert_eq!(pool.allow(&want), Some(dom0_raw.clone()));
        assert_eq!(pool.allow(&want).unwrap().name, dom0_raw.name);

        let want = new_acl!(new_ro "/c");
        assert_eq!(pool.allow(&want), Some(dom2.clone()));
        assert_eq!(pool.allow(&want).unwrap().name, dom2.name);
        let neq = pool.allow(&want) != Some(dom0_raw.clone());
        assert!(neq);
    }

    #[test]
    fn pool_equivalent2() {
        let mut pool = ResPool::new();
        let_dom!(pool, dom1, new_acl!(
            new_ro "/a",
            new_rw "/b"
        ));
        let_dom!(pool, dom2, new_acl!(
            new_ro "/a",
            new_rw "/c"
        ));

        // Artificial domain (i.e. not in the pool)
        let dom0_raw = dom1.new_intersect(&dom2).unwrap();

        let_dom!(pool, dom3, new_acl!(
            new_ro "/a"
        ));

        // Equivalent domain
        assert_eq!(&dom0_raw, &dom3);
        // But different domain
        let neq = dom0_raw.name != dom3.name;
        assert!(neq);

        // First intersect *after* last new_dom
        let want = new_acl!(new_ro "/a/x");
        assert_eq!(pool.allow(&want), Some(dom0_raw.clone()));
        assert_eq!(pool.allow(&want), Some(dom3.clone()));

        // Next intersect reuse the first one
        assert_eq!(dom0_raw.name, "dom1 ∩ dom2".to_string());
        assert_eq!(pool.allow(&want).unwrap().name, "dom1 ∩ dom2 ∩ dom3".to_string());
    }

    #[test]
    #[allow(unused_variables)]
    fn pool_equivalent3() {
        let mut pool = ResPool::new();
        let_dom!(pool, dom1, new_acl!(
            new_ro "/a",
            new_rw "/b"
        ));
        let_dom!(pool, dom2, new_acl!(
            new_ro "/a",
            new_rw "/c"
        ));

        // First intersect *before* last new_dom
        let want = new_acl!(new_ro "/a/x");
        assert_eq!(pool.allow(&want).unwrap().name, "dom1 ∩ dom2".to_string());

        let_dom!(pool, dom3, new_acl!(
            new_ro "/a"
        ));

        // Next intersect reuse the first one
        let want = new_acl!(new_ro "/a/x");
        assert_eq!(pool.allow(&want).unwrap().name, "dom1 ∩ dom2".to_string());
    }

    #[test]
    fn pool_equivalent4() {
        let mut pool = ResPool::new();
        let_dom!(pool, dom1, new_acl!(
            new_ro "/a",
            new_rw "/b"
        ));
        let_dom!(pool, dom2, new_acl!(
            new_ro "/a",
            new_rw "/b"
        ));

        // dom2 is redundant with dom1
        assert_eq!(dom2.name, "dom1".to_string());

        let dom0_raw = dom1.new_intersect(&dom2).unwrap();

        let want = new_acl!(new_ro "/a/x");
        assert_eq!(pool.allow(&want), Some(dom1.clone()));
        assert_eq!(pool.allow(&want), Some(dom2.clone()));
        assert_eq!(pool.allow(&want), Some(dom0_raw.clone()));
        assert_eq!(pool.allow(&want).unwrap().name, "dom1".to_string());
    }

    #[test]
    #[allow(unused_variables)]
    fn pool_underlays1() {
        let mut pool = ResPool::new();
        let_dom!(pool, dom1, new_acl!(
            new_ro "/a",
            new_rw "/b"
        ));
        let_dom!(pool, dom2, new_acl!(
            new_ro "/a",
            new_rw "/c"
        ));
        let_dom!(pool, dom3, new_acl!(
            new_ro "/a"
        ));

        let want = new_acl!(new_ro "/a/x");
        assert_eq!(pool.allow(&want).unwrap().name, "dom1 ∩ dom2 ∩ dom3".to_string());
        // FIXME: Only create an intersection domains, not new by pair (cf. underlays)
        assert_eq!(pool.allow(&want).unwrap().underlays.
                   iter().map(|x| x.name.as_str()).collect::<Vec<_>>(),
                   //["dom1", "dom2", "dom3"]);
                   ["dom1 ∩ dom2", "dom3"]);
    }

    #[test]
    #[allow(unused_variables)]
    fn pool_transition1() {
        let mut pool = ResPool::new();
        let_dom!(pool, dom1, new_acl!(
            new_rw "/a",
            new_rw "/f/g"
        ));
        let_dom!(pool, dom2, new_acl!(
            new_rw "/a",
            new_rw "/f/h"
        ));
        let_dom!(pool, dom3, new_acl!(
            new_rw "/a/b/c",
            new_rw "/a/d"
        ));
        let_dom!(pool, dom4, new_acl!(
            new_rw "/a/e"
        ));

        let current = pool.allow(&new_acl!(new_rw "/a/e/x"));
        let dom_check = dom1.new_intersect_all(&vec!(&dom2, &dom4)).unwrap();
        assert_eq!(dom_check, dom4);
        assert_eq!(current, Some(dom_check));

        let current = current.unwrap();
        let prev = current.clone();
        let next = current.reachable(&new_acl!(new_rw "/a/e/y")).unwrap();
        let current = current.transition(next);
        assert_eq!(current, Some(prev));

        let current = current.unwrap();
        let next = current.reachable(&new_acl!(new_rw "/a")).unwrap();
        let current = current.transition(next);
        let dom_check = dom1.new_intersect_all(&vec!(&dom2)).unwrap();
        assert_eq!(current, Some(dom_check));

        let current = current.unwrap();
        let next = current.reachable(&new_acl!(new_rw "/f/h")).unwrap();
        let current = current.transition(next);
        assert_eq!(current, Some(dom2.clone()));

        let current = current.unwrap();
        let next = current.reachable(&new_acl!(new_rw "/f/g"));
        assert_eq!(next, None);
        let current = current.transition(dom1);
        assert_eq!(current, None);
    }
}
