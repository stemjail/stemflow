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

#![allow(unused_features)]
#![feature(collections)]
#![feature(convert)]
#![feature(hash)]
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
use std::hash::{Hash, Hasher, SipHasher, hash};
use std::sync::Arc;

pub use fs::{new_path, FileAccess};

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

pub trait SetAccess {
    fn is_allowed(&self, access: &Arc<FileAccess>) -> bool;
    fn range_read<'a>(&'a self) -> Range<'a, Arc<FileAccess>>;
    fn range_write<'a>(&'a self) -> Range<'a, Arc<FileAccess>>;
}

pub trait Access {
    fn new_intersect(&self, other: Self) -> Option<Self>;
    fn new_intersect_all(&self, other: Vec<Self>) -> Option<Vec<Self>>;
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

fn vec2opt<T>(vec: Vec<T>) -> Option<Vec<T>> {
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
pub struct Domain {
    pub name: String,
    kind: DomainKind,
    pub acl: BTreeSet<Arc<FileAccess>>,
    underlays: BTreeSet<Arc<Domain>>,
}

// Do not check underlays: do not add duplicate domains
// Do not check name: omit equivalent domain with different name
impl PartialEq for Domain {
    // TODO: Check ptr value?
    fn eq(&self, other: &Self) -> bool {
        self.kind == self.kind &&
            self.acl == other.acl
    }
}

// Do not check underlays: optimize sorting
// Do not check name: optimize sorting
impl PartialOrd for Domain {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.acl.partial_cmp(&other.acl) {
            Some(Ordering::Equal) => self.kind.partial_cmp(&other.kind),
            pord => pord,
        }
    }
}

// Do not check underlays: optimize sorting
// Do not check name: optimize sorting
impl Ord for Domain {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.acl.cmp(&other.acl) {
            Ordering::Equal => self.kind.cmp(&other.kind),
            ord => ord,
        }
    }
}

impl Domain {
    /// The ressources should have been uniquified
    fn new(name: String, kind: DomainKind, acl: BTreeSet<Arc<FileAccess>>,
           underlays: BTreeSet<Arc<Domain>>) -> Domain {
        Domain {
            name: name,
            kind: kind,
            acl: acl,
            underlays: underlays,
        }
    }
}

/// Avoid recursive hashing by assuming the domain name is unique!
impl Hash for Domain {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.kind.hash(state);
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        write!(out, "{}", self.name)
    }
}

pub trait RcDomain {
    fn is_allowed(&self, access: &Arc<FileAccess>) -> bool;
    fn allow(&self, acl: &Vec<Arc<FileAccess>>) -> Option<Vec<Arc<FileAccess>>>;
    fn new_intersect(&self, other: &Self) -> Option<Self>;
    fn new_intersect_all(&self, others: &Vec<&Self>) -> Option<Self>;
    fn connect_names(&self, others: &Vec<&Self>, separator: &str) -> String;
    fn leaves(&self) -> BTreeSet<Self>;
    fn leaves_names(&self) -> Vec<String>;
    fn reachable(&self, acl: &Vec<Arc<FileAccess>>) -> Option<Self>;
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

// Hack to use Arc with self
impl RcDomain for Arc<Domain> {
    fn is_allowed(&self, access: &Arc<FileAccess>) -> bool {
        self.acl.is_allowed(access)
    }

    fn allow(&self, acl: &Vec<Arc<FileAccess>>) -> Option<Vec<Arc<FileAccess>>> {
        vec2opt(acl.iter().filter_map(
            |x| {
                if self.is_allowed(&x) {
                    Some(x.clone())
                } else {
                    None
                }
            }).collect())
    }

    // FIXME: Do not expose to the public API to avoid inconsistent ResPool
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
    // FIXME: Do not expose to the public API to avoid inconsistent ResPool
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
        names.connect(separator)
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

    /// Split the transition in two steps: transition(reachable(acl).unwrap())
    fn reachable(&self, acl: &Vec<Arc<FileAccess>>) -> Option<Self> {
        // Check if all acl are allowed
        let acl_all = |dom: &Self| {
            acl.iter().all(|x| dom.is_allowed(x))
        };
        if acl_all(self) {
            return Some(self.clone());
        }
        self.underlays.iter().fold(None,
            |prev, x| {
                if acl_all(x) {
                    match prev {
                        None => Some(x.clone()),
                        Some(p) => p.new_intersect(x),
                    }
                } else {
                    prev
                }
            })
    }

    /// Useful on the monitor side
    fn transition(self, target: Self) -> Option<Self> {
        if target == self {
            Some(self)
        } else {
            // Exact match
            match self.underlays.range(Bound::Included(&target), Bound::Included(&target)).next() {
                Some(x) => Some(x.clone()),
                None => None,
            }
        }
    }
}


// TODO: Remove all `fs` module references
pub struct ResPool {
    ressources: BTreeMap<Arc<FileAccess>, BTreeSet<Arc<Domain>>>,
    domains: BTreeSet<Arc<Domain>>,
}

impl ResPool {
    pub fn new() -> ResPool {
        ResPool {
            ressources: BTreeMap::new(),
            domains: BTreeSet::new(),
        }
    }

    /// Create a domain if it doesn't have a twin or return an existing equivalent domain (can have
    /// a different name).
    // FIXME: Check the domain name uniqueness (cf. domain hash)
    pub fn new_dom(&mut self, name: String, acl: Vec<Arc<FileAccess>>) -> Arc<Domain> {
        let acl: BTreeSet<_> = acl.uniquify().into_iter().collect();
        let dom = Arc::new(Domain::new(name, DomainKind::Final, acl, BTreeSet::new()));
        self.insert_dom(dom)
    }

    /// Record a domain if it doesn't have a twin or return an existing equivalent domain (can have
    /// a different name).
    pub fn insert_dom(&mut self, dom: Arc<Domain>) -> Arc<Domain> {
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
        dom
    }

    /// Get (or create) the tighter domain with all this ACL
    pub fn allow(&mut self, acl: &Vec<Arc<FileAccess>>) -> Option<Arc<Domain>> {
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

#[derive(Clone)]
pub enum Node {
    Access(Arc<FileAccess>),
    Dom(Arc<Domain>),
}

#[derive(Clone)]
pub struct Edge {
    source: Node,
    target: Node,
}

impl<'a> dot::Labeller<'a, Node, Edge> for ResPool {
    fn graph_id(&'a self) -> dot::Id<'a> {
        // Regex "[a-zA-Z_][a-zA-Z_0-9]*"
        dot::Id::new("G_stemflow").unwrap()
    }

    fn node_id(&'a self, node: &Node) -> dot::Id<'a> {
        let id = match *node {
            Node::Access(ref a) => format!("A_{}", hash::<_, SipHasher>(&a.path)),
            Node::Dom(ref d) => format!("D_{}", hash::<_, SipHasher>(d)),
        };
        // Regex "[a-zA-Z_][a-zA-Z_0-9]*"
        dot::Id::new(id).unwrap()
    }

    fn node_label(&'a self, node: &Node) -> dot::LabelText<'a> {
        let name = match *node {
            Node::Access(ref a) => format!("{}", a.path.display()),
            Node::Dom(ref d) => format!("{}", d).replace("∩", "&cap;"),
        };
        dot::LabelText::LabelStr(name.into_cow())
    }

    fn edge_label(&'a self, edge: &Edge) -> dot::LabelText<'a> {
        let name: Cow<_> = match edge.target {
            Node::Access(ref a) => format!("{}", a.action).into(),
            Node::Dom(..) => "transition".into(),
        };
        dot::LabelText::LabelStr(name)
    }
}

impl<'a> dot::GraphWalk<'a, Node, Edge> for ResPool {
    fn nodes(&self) -> dot::Nodes<'a, Node> {
        Cow::Owned(self.domains.iter().map(|x| Node::Dom(x.clone()))
            .chain(self.ressources.keys().map(|x| Node::Access(x.clone())))
            .collect())
    }

    fn edges(&'a self) -> dot::Edges<'a, Edge> {
        self.domains.iter().cloned().flat_map(|x| {
            x.underlays.iter().cloned()
                .map(|y| Edge { source: Node::Dom(x.clone()), target: Node::Dom(y) })
                .chain(x.acl.iter().cloned()
                       .map(|y| Edge { source: Node::Dom(x.clone()), target: Node::Access(y) }))
                .collect::<Vec<_>>().into_iter()
        }).collect::<Vec<_>>().into_cow()
    }

    fn source(&self, edge: &Edge) -> Node {
        edge.source.clone()
    }

    fn target(&self, edge: &Edge) -> Node {
        edge.target.clone()
    }
}
