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

#![cfg(not(test))]

#[macro_use(let_dom, new_acl)]
extern crate stemflow;

use std::sync::Arc;
use stemflow::{FileAccess, ResPool, absolute_path};

fn main() {
    let mut pool = ResPool::new();
    let_dom!(pool, dom1, new_acl!(
        new_ro "/home/doc",
        new_rw "/home/x",
        new_rw "/home/z",
        new_ro "/usr",
        new_rw "/tmp"
    ));
    println!("dom1: {:?}", dom1);

    let_dom!(pool, dom2, new_acl!(
        new_rw "/home/doc/foo",
        new_ro "/home",
        new_ro "/home/z",
        new_ro "/usr",
        new_rw "/tmp"
    ));
    println!("dom2: {:?}", dom2);

    let want1 = new_acl!(new_rw "/home/doc/foo/bar");
    println!("want1: {:?}", want1);
    println!("allow: {:?}", match pool.allow(&want1.clone()) {
        Some(d) => d.name.clone(),
        None => "-".to_string(),
        });
}
