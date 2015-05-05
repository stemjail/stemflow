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

#![feature(rustc_private)]

#[macro_use(let_dom, new_acl)]
extern crate stemflow;
extern crate graphviz;

use std::fs::File;
use std::sync::Arc;
use stemflow::{new_path, FileAccess, ResPool, RcDomain};

#[allow(unused_variables)]
fn main() {
    // Same as fs::tests::pool_transition1()
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
    let _ = graphviz::render(&pool, &mut File::create("test2.dot").unwrap());
}
