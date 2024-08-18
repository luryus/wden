use maybe_owned::MaybeOwned;

use super::{
    api::CipherItem,
    cipher::{decrypt_item_keys, EncMacKeys},
};

pub fn resolve_item_keys<'a, 'b, F>(
    item: &'a CipherItem,
    user_keys: MaybeOwned<'a, EncMacKeys>,
    get_org_key: F,
) -> Option<MaybeOwned<'a, EncMacKeys>>
where
    F: for<'c> Fn(&'c String, &'c EncMacKeys) -> Option<MaybeOwned<'a, EncMacKeys>>,
{
    // If an item-specific key is defined, these base keys are used to decrypt that.
    // Otherwise these keys are directly used to decrypt the item details
    let base_keys: MaybeOwned<'a, EncMacKeys> = match &item.organization_id {
        Some(oid) => get_org_key(oid, &user_keys)?,
        None => user_keys,
    };

    match &item.key {
        Some(item_key) => decrypt_item_keys(&base_keys, item_key)
            .inspect_err(|e| log::warn!("Decrypting item keys failed: {e}"))
            .ok()
            .map(|k| k.into()),
        None => Some(base_keys),
    }
}
