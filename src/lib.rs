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

#![cfg_attr(test, feature(convert))]

#![feature(append)]
#![feature(btree_range)]
#![feature(collections)]
#![feature(collections_bound)]
#![feature(into_cow)]
#![feature(rustc_private)]

extern crate collections;
extern crate graphviz;

use collections::{Bound, BTreeMap, BTreeSet};
use collections::btree_map::Entry;
use collections::btree_set::Range;
use graphviz as dot;
use std::borrow::{Cow, IntoCow};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher, SipHasher};
use std::ops::Deref;
use std::sync::Arc;

pub use fs::{absolute_path, FileAccess, RefAccess};

macro_rules! set {
    ($($v: expr),+) => ({
        let mut b = BTreeSet::new();
        $(let _ = b.insert($v);)+
        b
    })
}

mod fs;

pub trait VecAccess {
    fn uniquify(mut self) -> Self;
}

pub trait SetAccess<A> where A: Access {
    fn is_allowed(&self, access: &A) -> bool;
    fn insert_dedup(&mut self, access: A) -> bool;
    fn range_read<'a>(&'a self) -> Range<'a, A>;
    fn range_write<'a>(&'a self) -> Range<'a, A>;

    fn insert_dedup_all<I>(&mut self, access_iter: I) -> bool where I: Iterator<Item=A> {
        access_iter.fold(true, |prev, x| self.insert_dedup(x) && prev)
    }
}

pub trait Access: Deref<Target=FileAccess> + Clone + fmt::Debug + Eq + Ord + Sized {
    fn new(inner: FileAccess) -> Self;

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

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    Read,
    Write,
}

impl fmt::Display for Action {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let txt = match *self {
            Action::Read => "read",
            Action::Write => "write",
        };
        write!(out, "{}", txt)
    }
}

fn vec2opt<A>(vec: Vec<A>) -> Option<Vec<A>> {
    if vec.len() == 0 {
        None
    } else {
        Some(vec)
    }
}

fn set2opt<T>(list: BTreeSet<T>) -> Option<BTreeSet<T>> where T: Ord {
    if list.len() == 0 {
        None
    } else {
        Some(list)
    }
}

/// Intersection domains should precede final domain to allow more transitions
// TODO: Check order and priority
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
enum DomainKind {
    Intersection = 1,
    Final = 2,
}

#[derive(Eq, Debug)]
pub struct Domain<A> where A: Access {
    pub name: String,
    kind: DomainKind,
    pub acl: BTreeSet<A>,
    underlays: BTreeSet<Arc<Domain<A>>>,
}

// Do not check underlays: do not add duplicate domains
// Do not check name: omit equivalent domain with different name
impl<A> PartialEq for Domain<A> where A: Access {
    // TODO: Check ptr value?
    fn eq(&self, other: &Self) -> bool {
        self.kind == self.kind &&
            self.acl == other.acl
    }
}

// Do not check underlays: optimize sorting
// Do not check name: optimize sorting
impl<A> PartialOrd for Domain<A> where A: Access {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.acl.partial_cmp(&other.acl) {
            Some(Ordering::Equal) => self.kind.partial_cmp(&other.kind),
            pord => pord,
        }
    }
}

// Do not check underlays: optimize sorting
// Do not check name: optimize sorting
impl<A> Ord for Domain<A> where A: Access {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.acl.cmp(&other.acl) {
            Ordering::Equal => self.kind.cmp(&other.kind),
            ord => ord,
        }
    }
}

impl<A> Domain<A> where A: Access {
    /// The ressources should have been uniquified
    fn new(name: String, kind: DomainKind, acl: BTreeSet<A>,
           underlays: BTreeSet<Arc<Domain<A>>>) -> Domain<A> {
        Domain {
            name: name,
            kind: kind,
            acl: acl,
            underlays: underlays,
        }
    }
}

/// Avoid recursive hashing by assuming the domain name is unique!
impl<A> Hash for Domain<A> where A: Access {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.kind.hash(state);
    }
}

impl<A> fmt::Display for Domain<A> where A: Access {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        write!(out, "{}", self.name)
    }
}

pub trait RefDom<A> where A: Access, Self: Sized {
    fn is_allowed(&self, access: &A) -> bool;
    fn allow(&self, acl: &Vec<A>) -> Option<Vec<A>>;
    fn reachable(&self, acl: &Vec<A>) -> Option<Self>;
    fn transition(self, target: Self) -> Option<Self>;
}

macro_rules! get_allow {
    ($a: expr, $b: expr) => {
        $a.acl.iter().filter_map(
            |x| {
                if $b.is_allowed(&x) {
                    Some(x.clone())
                } else {
                    None
                }
            })
    }
}

// Hack to use Rc/Arc with self
impl<A> RefDom<A> for Arc<Domain<A>> where A: Access {
    fn is_allowed(&self, access: &A) -> bool {
        self.acl.is_allowed(access)
    }

    fn allow(&self, acl: &Vec<A>) -> Option<Vec<A>> {
        vec2opt(acl.iter().filter_map(
            |x| {
                if self.is_allowed(&x) {
                    Some(x.clone())
                } else {
                    None
                }
            }).collect())
    }

    /// Split the transition in two steps: transition(reachable(acl).unwrap())
    fn reachable(&self, acl: &Vec<A>) -> Option<Self> {
        // Check if all ACL are allowed
        let denied: Vec<_> = acl.iter().filter(|x| !self.is_allowed(x)).cloned().collect();
        if denied.is_empty() {
            return Some(self.clone());
        }
        self.underlays.iter().fold(None,
            |prev, x| {
                // Do not need to re-check the current (domains) allowed ACL because underlays
                // domains are part of the current intersection.
                match x.reachable(&denied) {
                    Some(dom) => match prev {
                        None => Some(dom),
                        Some(p) => p.new_intersect(&dom),
                    },
                    None => prev,
                }
            })
    }

    /// Useful on the monitor side
    fn transition(self, target: Self) -> Option<Self> {
        if target == self {
            Some(self)
        } else {
            self.transition_underlays(&target)
        }
    }
}

trait RefDomPriv where Self: Sized {
    fn new_intersect(&self, other: &Self) -> Option<Self>;
    fn new_intersect_all(&self, others: &Vec<&Self>) -> Option<Self>;
    fn connect_names(&self, others: &Vec<&Self>, separator: &str) -> String;
    fn leaves_names(&self) -> Vec<String>;
    fn leaves(&self) -> BTreeSet<Self>;
    fn transition_underlays(&self, target: &Self) -> Option<Self>;
}

impl<A> RefDomPriv for Arc<Domain<A>> where A: Access {
    /// Get an intersection domain
    fn new_intersect(&self, other: &Self) -> Option<Self> {
        // TODO: Replace with BTree range
        let self_allow = get_allow!(self, other);
        let other_allow = get_allow!(other, self);
        let acl: Vec<_> = self_allow.chain(other_allow).collect();
        // No new ressources to uniquify so it's OK
        let acl = acl.uniquify();
        let acl: BTreeSet<_> = acl.into_iter().collect();
        // No need to dedup acl
        if acl.len() == 0 {
            // Non-overlapping domains
            None
        } else {
            // Overlapping domains
            Some(Arc::new(Domain::new(self.connect_names(&vec!(other), " ∩ "),
                DomainKind::Intersection, acl, set!(self.clone(), other.clone()))))
        }
    }

    // FIXME: Only create an intersection domains, not new by pair (cf. underlays)
    // TODO: Do flat intersections
    fn new_intersect_all(&self, others: &Vec<&Self>) -> Option<Self> {
        others.iter().fold(Some(self.clone()),
            |prev, x| {
                match prev {
                    None => None,
                    Some(p) => p.new_intersect(x),
                }
            })
    }

    fn connect_names(&self, others: &Vec<&Self>, separator: &str) -> String {
        let mut names = others.iter().fold(self.leaves_names(),
            |mut prev, x| {
                prev.append(&mut x.leaves_names());
                prev
            });
        names.sort();
        names.dedup();
        names.join(separator)
    }

    // TODO: Return Vec<&str>
    fn leaves_names(&self) -> Vec<String> {
        // TODO: Forbid domain with same name (and return a BTreeSet)
        self.leaves().iter().map(|x| x.name.clone()).collect()
    }

    fn leaves(&self) -> BTreeSet<Self> {
        if self.underlays.len() == 0 {
            set!(self.clone())
        } else {
            // Recursive call
            self.underlays.iter().flat_map(|x| x.leaves().into_iter()).collect()
        }
    }

    fn transition_underlays(&self, target: &Self) -> Option<Self> {
        match self.underlays.range(Bound::Included(target), Bound::Included(target)).next() {
            Some(x) => Some(x.clone()),
            None => {
                for dom in self.underlays.iter() {
                    match dom.transition_underlays(&target) {
                        Some(d) => return Some(d),
                        None => {}
                    }
                }
                None
            }
        }
    }
}


// TODO: Remove all `fs` module references
pub struct ResPool<A> where A: Access {
    ressources: BTreeMap<A, BTreeSet<Arc<Domain<A>>>>,
    domains: BTreeSet<Arc<Domain<A>>>,
}

impl<A> ResPool<A> where A: Access {
    pub fn new() -> ResPool<A> {
        ResPool {
            ressources: BTreeMap::new(),
            domains: BTreeSet::new(),
        }
    }

    /// Create a domain if it doesn't have a twin or return an existing equivalent domain (can have
    /// a different name).
    // FIXME: Check the domain name uniqueness (cf. domain hash)
    pub fn new_dom(&mut self, name: String, acl: Vec<A>) -> Arc<Domain<A>> {
        let acl: BTreeSet<_> = acl.uniquify().into_iter().collect();
        let dom = Arc::new(Domain::new(name, DomainKind::Final, acl, BTreeSet::new()));
        self.insert_dom(dom)
    }

    pub fn contains_dom(&self, dom: &Arc<Domain<A>>) -> bool {
        self.domains.contains(dom)
    }

    /// Record a domain if it doesn't have a twin or return an existing equivalent domain (can have
    /// a different name).
    pub fn insert_dom(&mut self, dom: Arc<Domain<A>>) -> Arc<Domain<A>> {
        // If the domain is already registered
        if ! self.domains.insert(dom.clone()) {
            // A BTreeSet::entry() would avoid unwrap()
            return self.domains.range(Bound::Included(&dom), Bound::Included(&dom)).
                next().unwrap().clone();
        }

        for access in dom.acl.iter() {
            match self.ressources.entry(access.clone()) {
                Entry::Vacant(view) => {
                    let _ = view.insert(set!(dom.clone()));
                }
                Entry::Occupied(view) => {
                    let _ = view.into_mut().insert(dom.clone());
                }
            }
        }

        // Recursive domain insertion
        for sub in dom.underlays.iter() {
            if ! self.contains_dom(sub) {
                let _ = self.insert_dom(sub.clone());
            }
        }
        dom
    }

    /// Get (or create) the tighter domain with all this ACL
    pub fn allow(&mut self, acl: &Vec<A>) -> Option<Arc<Domain<A>>> {
        let doms = {
            let allow = |access| {
                // Take all domains globing the access
                set2opt(self.ressources.range(Bound::Included(access), Bound::Unbounded).
                    take_while(|&(k, _)| k.action == access.action).
                    filter(|&(k, _)| k.contains(&*access)).
                    fold(BTreeSet::new(), |prev, (_, v)| prev.union(v).cloned().collect()))
            };
            let mut aci = acl.iter();
            let doms = match aci.next() {
                Some(x) => {
                    match allow(x) {
                        Some(y) => y,
                        None => return None,
                    }
                }
                None => return None,
            };
            aci.fold(Some(doms), |prev, access| {
                match prev {
                    Some(p) => {
                        match allow(access) {
                            Some(da) => set2opt(p.intersection(&da).cloned().collect()),
                            None => None,
                        }
                    }
                    None => None,
                }
            })
        };
        match doms {
            Some(doms) => {
                let mut domi = doms.iter();
                match domi.next() {
                    Some(d) => {
                        match d.new_intersect_all(&domi.collect()) {
                            Some(d) => Some(self.insert_dom(d)),
                            None => None,
                        }
                    }
                    None => None,
                }
            }
            None => None,
        }
    }
}

#[derive(Clone, Eq)]
pub enum Node<A> where A: Access {
    Access(A),
    Dom(Arc<Domain<A>>),
}

/// A node do not take into account the access mode: read, write.
impl<A> PartialEq for Node<A> where A: Access {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (&Node::Access(ref x), &Node::Access(ref y)) => x.path == y.path,
            (&Node::Dom(ref x), &Node::Dom(ref y)) => {
                // Same as Hash implementation for Domain (name must be unique)
                x.kind == y.kind && x.name == y.name
            }
            (_, _) => false,
        }
    }
}

impl<A> PartialOrd for Node<A> where A: Access {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (&Node::Access(ref x), &Node::Access(ref y)) => x.path.partial_cmp(&y.path),
            (&Node::Dom(ref x), &Node::Dom(ref y)) => {
                // Same as Hash implementation for Domain (name must be unique)
                match x.kind.partial_cmp(&y.kind) {
                    None => x.name.partial_cmp(&y.name),
                    o => o,
                }
            }
            (_, _) => None,
        }
    }
}

impl<A> Ord for Node<A> where A: Access {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (&Node::Access(ref x), &Node::Access(ref y)) => x.path.cmp(&y.path),
            (&Node::Dom(ref x), &Node::Dom(ref y)) => {
                // Same as Hash implementation for Domain (name must be unique)
                match x.kind.cmp(&y.kind) {
                    Ordering::Equal => x.name.cmp(&y.name),
                    o => o,
                }
            }
            (&Node::Dom(_), _) => Ordering::Less,
            (&Node::Access(_), _) => Ordering::Greater,
        }
    }
}

#[derive(Clone, Eq)]
pub struct Edge<A> where A: Access {
    source: Node<A>,
    target: Node<A>,
}

/// An edge take into account the target kind: domain, access/read, access/write.
impl<A> PartialEq for Edge<A> where A: Access {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source &&
            match (&self.target, &other.target) {
                (&Node::Access(ref x), &Node::Access(ref y)) => x == y,
                (s, o) => s == o,
            }
    }
}

impl<A> PartialOrd for Edge<A> where A: Access {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.source.partial_cmp(&other.source) {
            None | Some(Ordering::Equal) => {
                match (&self.target, &other.target) {
                    (&Node::Access(ref x), &Node::Access(ref y)) => x.partial_cmp(y),
                    (s, o) => s.partial_cmp(o),
                }
            }
            o => o,
        }
    }
}

impl<A> Ord for Edge<A> where A: Access {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.source.cmp(&other.source) {
            Ordering::Equal => {
                match (&self.target, &other.target) {
                    (&Node::Access(ref x), &Node::Access(ref y)) => x.cmp(y),
                    (s, o) => s.cmp(o),
                }
            }
            o => o,
        }
    }
}

fn hash<T: Hash>(t: &T) -> u64 {
    let mut s = SipHasher::new();
    t.hash(&mut s);
    s.finish()
}

impl<'a, A> dot::Labeller<'a, Node<A>, Edge<A>> for ResPool<A> where A: Access {
    fn graph_id(&'a self) -> dot::Id<'a> {
        // Regex "[a-zA-Z_][a-zA-Z_0-9]*"
        dot::Id::new("G_stemflow").unwrap()
    }

    fn node_id(&'a self, node: &Node<A>) -> dot::Id<'a> {
        let id = match *node {
            Node::Access(ref a) => format!("A_{}", hash(&a.path)),
            Node::Dom(ref d) => format!("D_{}", hash(d)),
        };
        // Regex "[a-zA-Z_][a-zA-Z_0-9]*"
        dot::Id::new(id).unwrap()
    }

    fn node_label(&'a self, node: &Node<A>) -> dot::LabelText<'a> {
        let name = match *node {
            Node::Access(ref a) => format!("{}", a.path.display()),
            Node::Dom(ref d) => format!("{}", d).replace("∩", "&cap;"),
        };
        dot::LabelText::LabelStr(name.into_cow())
    }

    fn edge_label(&'a self, edge: &Edge<A>) -> dot::LabelText<'a> {
        let name: Cow<_> = match edge.target {
            Node::Access(ref a) => format!("{}", a.action).into(),
            Node::Dom(..) => "transition".into(),
        };
        dot::LabelText::LabelStr(name)
    }
}

impl<'a, A> dot::GraphWalk<'a, Node<A>, Edge<A>> for ResPool<A> where A: Access {
    fn nodes(&self) -> dot::Nodes<'a, Node<A>> {
        let mut nodes: Vec<_> = self.domains.iter().map(|x| Node::Dom(x.clone()))
            .chain(self.ressources.keys().map(|x| Node::Access(x.clone())))
            .collect();
        nodes.sort();
        nodes.dedup();
        nodes.into_cow()
    }

    fn edges(&'a self) -> dot::Edges<'a, Edge<A>> {
        let mut edges: Vec<_> = self.domains.iter().cloned().flat_map(|x| {
            x.underlays.iter().cloned()
                .map(|y| Edge { source: Node::Dom(x.clone()), target: Node::Dom(y) })
                .chain(x.acl.iter().cloned()
                       .map(|y| Edge { source: Node::Dom(x.clone()), target: Node::Access(y) }))
                .collect::<Vec<_>>().into_iter()
        }).collect();
        edges.sort();
        edges.dedup();
        edges.into_cow()
    }

    fn source(&self, edge: &Edge<A>) -> Node<A> {
        edge.source.clone()
    }

    fn target(&self, edge: &Edge<A>) -> Node<A> {
        edge.target.clone()
    }
}
