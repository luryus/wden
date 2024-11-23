use std::collections::HashMap;

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use simsearch::SimSearch;

use crate::bitwarden::{self, api::CipherData};

use super::data::{StatefulUserData, Unlocked};

pub fn search_items(term: &str, simsearch: &SimSearch<String>) -> Option<Vec<String>> {
    if term.is_empty() {
        return None;
    }

    Some(simsearch.search(term))
}

pub fn get_search_index(ud: &StatefulUserData<Unlocked>) -> SimSearch<String> {
    let mut ss = SimSearch::new();

    if let Some(tokenized_rows) = get_tokenized_rows(ud) {
        for (k, tokens) in tokenized_rows {
            // SimSearch will still tokenize (split) each of the tokens
            // that are passed here. Passing them this way just avoids
            // concatenating them into a string.
            let tokens: Vec<_> = tokens.iter().map(|s| s.as_str()).collect();
            ss.insert_tokens(k.clone(), &tokens);
        }
    }

    ss
}

fn get_tokenized_rows(ud: &StatefulUserData<Unlocked>) -> Option<HashMap<String, Vec<String>>> {
    let vd = ud.vault_data();
    let org_keys = ud.get_org_keys_for_vault();
    let user_keys = ud.decrypt_keys()?;

    let res = vd
        .par_iter()
        .filter_map(|(k, v)| {
            // Get appropriate keys for this item
            let item_keys =
                bitwarden::keys::resolve_item_keys(v, (&user_keys).into(), |oid, _uk| {
                    org_keys.get(oid).map(|k| k.into())
                })?;

            // All items: name
            let mut tokens = vec![v.name.decrypt_to_string(&item_keys)];
            // Login items: url and username
            if let CipherData::Login(l) = &v.data {
                tokens.push(l.username.decrypt_to_string(&item_keys));
                tokens.push(l.uri.decrypt_to_string(&item_keys));
            };

            Some((k.clone(), tokens))
        })
        .collect();

    Some(res)
}
