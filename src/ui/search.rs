use std::collections::HashMap;

use simsearch::SimSearch;

use crate::bitwarden::api::CipherData;

use super::data::UserData;

pub fn update_search_index(ud: &mut UserData) {
    ud.simsearch = Some(get_search_index(ud));
}

pub fn search_items(term: &str, ud: &UserData) -> Option<Vec<String>> {
    if term.is_empty() {
        return None;
    }

    Some(ud.simsearch.as_ref()?.search(term))
}

fn get_search_index(ud: &UserData) -> SimSearch<String> {
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

fn get_tokenized_rows(ud: &UserData) -> Option<HashMap<String, Vec<String>>> {
    let vd = ud.vault_data.as_ref()?;
    let org_keys = ud.get_org_keys_for_vault()?;
    let (user_enc_key, user_mac_key) = ud.decrypt_keys()?;

    let res = vd
        .iter()
        .filter_map(|(k, v)| {
            // Get appropriate keys for this item
            let (ec, mc) = match &v.organization_id {
                Some(oid) => match org_keys.get(oid) {
                    Some(keys) => (&keys.0, &keys.1),
                    None => return None,
                },
                _ => (&user_enc_key, &user_mac_key),
            };

            // All items: name
            let mut tokens = vec![v.name.decrypt_to_string(ec, mc)];
            // Login items: url and username
            if let CipherData::Login(l) = &v.data {
                tokens.push(l.username.decrypt_to_string(ec, mc));
                tokens.push(l.uri.decrypt_to_string(ec, mc));
            };

            Some((k.clone(), tokens))
        })
        .collect();

    Some(res)
}
