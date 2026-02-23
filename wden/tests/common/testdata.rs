use base64::Engine;
use rand::RngCore;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use sha1::Digest;
use wden::bitwarden::{
    self,
    api::{CipherData, CipherItem, LoginItemUri, SecureNoteItem},
    cipher::{Cipher, CipherError, EncMacKeys},
};

use super::api::{
    CreateCollectionRequest, CreateOrgCipherRequest, CreateOrganizationRequest, OrganizationKeyPair,
};

pub struct NoteItem {
    pub name: &'static str,
    notes: &'static str,
}

pub struct LoginItem {
    pub name: &'static str,
    pub notes: &'static str,

    pub username: &'static str,
    pub password: &'static str,
    pub uri: &'static str,
}

pub struct CardItem {
    pub name: &'static str,
    notes: &'static str,

    brand: &'static str,
    cardholder_name: &'static str,
    code: &'static str,
    exp_month: &'static str,
    exp_year: &'static str,
    number: &'static str,
}

pub struct Organization {
    pub name: &'static str,
    collection_name: &'static str,
}

pub struct Collection {
    pub name: &'static str,
}

// --- Personal items ---
pub const PERSONAL_NOTE_1: NoteItem = NoteItem {
    name: "Note 1",
    notes: "Note 1 content",
};
pub const PERSONAL_NOTE_2: NoteItem = NoteItem {
    name: "Note 2",
    notes: "Note 2 content",
};
pub const PERSONAL_LOGIN_1: LoginItem = LoginItem {
    name: "Login 1",
    notes: "Login 1 comment",
    username: "user1@user1.com",
    password: "password1",
    uri: "site1.com",
};
pub const PERSONAL_LOGIN_2: LoginItem = LoginItem {
    name: "Login 2",
    notes: "Login 2 comment",
    username: "user2@user2.com",
    password: "password2",
    uri: "site2.com",
};
pub const PERSONAL_LOGIN_3: LoginItem = LoginItem {
    name: "Login 3",
    notes: "Login 3 comment",
    username: "user3@user3.com",
    password: "password3",
    uri: "site3.com",
};
pub const PERSONAL_CARD_1: CardItem = CardItem {
    name: "Card 1",
    notes: "Card 1 comment",
    brand: "Visa",
    cardholder_name: "Card1 Holder",
    code: "123",
    exp_month: "11",
    exp_year: "28",
    number: "1234123412341234",
};

// --- Org 1 items, collection 1 ---
pub const ORG_1_COLL_1_LOGIN_1: LoginItem = LoginItem {
    name: "Org 1 Coll 1 Login 1",
    notes: "Org 1 Coll 1 Login 1 comment",
    username: "user1@org1coll1.com",
    password: "password1",
    uri: "site1.com",
};
pub const ORG_1_COLL_1_LOGIN_2: LoginItem = LoginItem {
    name: "Org 1 Coll 1 Login 2",
    notes: "Org 1 Coll 1 Login 2 comment",
    username: "user2@org1coll1.com",
    password: "password2",
    uri: "site2.com",
};
pub const ORG_1_COLL_1_LOGIN_3: LoginItem = LoginItem {
    name: "Org 1 Coll 1 Login 3",
    notes: "Org 1 Coll 1 Login 3 comment",
    username: "user3@org1coll1.com",
    password: "password3",
    uri: "site3.com",
};

// --- Org 1 items, collection 2 ---
pub const ORG_1_COLL_2_LOGIN_1: LoginItem = LoginItem {
    name: "Org 1 Coll 2 Login 1",
    notes: "Org 1 Coll 2 Login 1 comment",
    username: "user1@org1coll2.com",
    password: "password1",
    uri: "site1.com",
};
pub const ORG_1_COLL_2_LOGIN_2: LoginItem = LoginItem {
    name: "Org 1 Coll 2 Login 2",
    notes: "Org 1 Coll 2 Login 2 comment",
    username: "user2@org1coll2.com",
    password: "password2",
    uri: "site2.com",
};
pub const ORG_1_COLL_2_LOGIN_3: LoginItem = LoginItem {
    name: "Org 1 Coll 2 Login 3",
    notes: "Org 1 Coll 2 Login 3 comment",
    username: "user3@org1coll2.com",
    password: "password3",
    uri: "site3.com",
};

// --- Org 2 items, collection 3 ---
pub const ORG_2_COLL_3_LOGIN_1: LoginItem = LoginItem {
    name: "Org 2 Coll 3 Login 1",
    notes: "Org 2 Coll 3 Login 1 comment",
    username: "user1@org2coll3.com",
    password: "password1",
    uri: "site1.com",
};
pub const ORG_2_COLL_3_LOGIN_2: LoginItem = LoginItem {
    name: "Org 2 Coll 3 Login 2",
    notes: "Org 2 Coll 3 Login 2 comment",
    username: "user2@org2coll3.com",
    password: "password2",
    uri: "site2.com",
};
pub const ORG_2_COLL_3_LOGIN_3: LoginItem = LoginItem {
    name: "Org 2 Coll 3 Login 3",
    notes: "Org 2 Coll 3 Login 3 comment",
    username: "user3@org2coll3.com",
    password: "password3",
    uri: "site3.com",
};

// --- Organizations ---
pub const ORG_1: Organization = Organization {
    name: "Org 1",
    collection_name: "Default coll",
};
pub const ORG_2: Organization = Organization {
    name: "Org 2",
    collection_name: "Default coll",
};

// --- Collections ---
pub const COLL_1: Collection = Collection { name: "Coll 1" };
pub const COLL_2: Collection = Collection { name: "Coll 2" };
pub const COLL_3: Collection = Collection { name: "Coll 3" };

// --- Generator/conversion functions ---
pub fn organizations(
    email: &str,
    user_priv_key: &bitwarden::cipher::DerPrivateKey,
) -> Vec<(CreateOrganizationRequest, EncMacKeys)> {
    [ORG_1, ORG_2]
        .into_iter()
        .map(|x| {
            let user_pub_key = user_priv_key.public_key().unwrap();

            let mut org_share_key = Box::pin([0u8; 512 / 8]);
            rand::thread_rng().fill_bytes(org_share_key.as_mut_slice());

            let enc_org_share_key =
                Cipher::encrypt_pub_key(org_share_key.as_slice(), &user_pub_key).unwrap();

            let org_priv_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
            let org_enc_mac_keys = EncMacKeys::from_slice(org_share_key.as_slice()).unwrap();
            let org_priv_key_encoded = org_priv_key.to_pkcs8_der().unwrap();
            let enc_org_priv_key =
                Cipher::encrypt(org_priv_key_encoded.as_bytes(), &org_enc_mac_keys).unwrap();
            let org_pub_key = base64::prelude::BASE64_STANDARD.encode(
                org_priv_key
                    .to_public_key()
                    .to_public_key_der()
                    .unwrap()
                    .as_bytes(),
            );

            let enc_collection_name =
                Cipher::encrypt(x.collection_name.as_bytes(), &org_enc_mac_keys).unwrap();

            (
                CreateOrganizationRequest {
                    key: enc_org_share_key,
                    keys: OrganizationKeyPair {
                        encrypted_private_key: enc_org_priv_key,
                        public_key: org_pub_key,
                    },
                    name: x.name,
                    billing_email: email.to_string(),
                    collection_name: enc_collection_name,
                    initiation_path: "",
                    plan_type: 0,
                },
                org_enc_mac_keys,
            )
        })
        .collect()
}

pub fn collections(org_ids_keys: &[(String, EncMacKeys)]) -> Vec<CreateCollectionRequest> {
    assert_eq!(2, org_ids_keys.len());

    [
        (COLL_1, &org_ids_keys[0]),
        (COLL_2, &org_ids_keys[0]),
        (COLL_3, &org_ids_keys[1]),
    ]
    .into_iter()
    .map(|(c, (org_id, org_key))| {
        let name_enc = Cipher::encrypt(c.name.as_bytes(), org_key).unwrap();

        CreateCollectionRequest {
            name: name_enc,
            org_id: org_id.to_owned(),
            external_id: "",
            groups: [],
            users: [],
        }
    })
    .collect()
}

pub fn items(
    user_keys: &EncMacKeys,
    org_ids_keys: &[(String, EncMacKeys)],
    collection_ids: &[String],
) -> Result<Vec<CreateOrgCipherRequest>, CipherError> {
    assert_eq!(2, org_ids_keys.len());
    assert_eq!(3, collection_ids.len());

    let user_items = [
        encrypt_card(user_keys, &PERSONAL_CARD_1, None, None)?,
        encrypt_login(user_keys, &PERSONAL_LOGIN_1, None, None)?,
        encrypt_login(user_keys, &PERSONAL_LOGIN_2, None, None)?,
        encrypt_login(user_keys, &PERSONAL_LOGIN_3, None, None)?,
        encrypt_note(user_keys, &PERSONAL_NOTE_1, None, None)?,
        encrypt_note(user_keys, &PERSONAL_NOTE_2, None, None)?,
    ];

    let coll1_items = [
        encrypt_login(
            &org_ids_keys[0].1,
            &ORG_1_COLL_1_LOGIN_1,
            Some(&collection_ids[0]),
            Some(&org_ids_keys[0].0),
        )?,
        encrypt_login(
            &org_ids_keys[0].1,
            &ORG_1_COLL_1_LOGIN_2,
            Some(&collection_ids[0]),
            Some(&org_ids_keys[0].0),
        )?,
        encrypt_login(
            &org_ids_keys[0].1,
            &ORG_1_COLL_1_LOGIN_3,
            Some(&collection_ids[0]),
            Some(&org_ids_keys[0].0),
        )?,
    ];

    let coll2_items = [
        encrypt_login(
            &org_ids_keys[0].1,
            &ORG_1_COLL_2_LOGIN_1,
            Some(&collection_ids[1]),
            Some(&org_ids_keys[0].0),
        )?,
        encrypt_login(
            &org_ids_keys[0].1,
            &ORG_1_COLL_2_LOGIN_2,
            Some(&collection_ids[1]),
            Some(&org_ids_keys[0].0),
        )?,
        encrypt_login(
            &org_ids_keys[0].1,
            &ORG_1_COLL_2_LOGIN_3,
            Some(&collection_ids[1]),
            Some(&org_ids_keys[0].0),
        )?,
    ];

    let coll3_items = [
        encrypt_login(
            &org_ids_keys[1].1,
            &ORG_2_COLL_3_LOGIN_1,
            Some(&collection_ids[2]),
            Some(&org_ids_keys[1].0),
        )?,
        encrypt_login(
            &org_ids_keys[1].1,
            &ORG_2_COLL_3_LOGIN_2,
            Some(&collection_ids[2]),
            Some(&org_ids_keys[1].0),
        )?,
        encrypt_login(
            &org_ids_keys[1].1,
            &ORG_2_COLL_3_LOGIN_3,
            Some(&collection_ids[2]),
            Some(&org_ids_keys[1].0),
        )?,
    ];

    Ok(user_items
        .into_iter()
        .chain(coll1_items)
        .chain(coll2_items)
        .chain(coll3_items)
        .collect())
}

fn encrypt_card(
    keys: &EncMacKeys,
    item: &CardItem,
    collection_id: Option<&str>,
    org_id: Option<&str>,
) -> Result<CreateOrgCipherRequest, CipherError> {
    let brand = Cipher::encrypt(item.brand.as_bytes(), keys)?;
    let cardholder = Cipher::encrypt(item.cardholder_name.as_bytes(), keys)?;
    let code = Cipher::encrypt(item.code.as_bytes(), keys)?;
    let exp_month = Cipher::encrypt(item.exp_month.as_bytes(), keys)?;
    let exp_year = Cipher::encrypt(item.exp_year.as_bytes(), keys)?;
    let name = Cipher::encrypt(item.name.as_bytes(), keys)?;
    let notes = Cipher::encrypt(item.notes.as_bytes(), keys)?;
    let number = Cipher::encrypt(item.number.as_bytes(), keys)?;

    let collection_ids: Vec<String> = collection_id.into_iter().map(|x| x.to_owned()).collect();

    let item = CipherItem {
        collection_ids,
        id: String::default(),
        name,
        notes,
        organization_id: org_id.map(|x| x.to_owned()),
        key: None,
        favorite: false,
        data: CipherData::Card(Box::new(bitwarden::api::CardItem {
            brand,
            cardholder_name: cardholder,
            code,
            exp_month,
            exp_year,
            number,
        })),
    };

    let personal_cipher = item.into();
    let collection_ids = collection_id.into_iter().map(|x| x.to_owned()).collect();
    Ok(CreateOrgCipherRequest {
        cipher: personal_cipher,
        collection_ids,
    })
}

fn encrypt_login(
    keys: &EncMacKeys,
    item: &LoginItem,
    collection_id: Option<&str>,
    org_id: Option<&str>,
) -> Result<CreateOrgCipherRequest, CipherError> {
    let password = Cipher::encrypt(item.password.as_bytes(), keys)?;
    let uri = Cipher::encrypt(item.uri.as_bytes(), keys)?;
    let username = Cipher::encrypt(item.username.as_bytes(), keys)?;
    let name = Cipher::encrypt(item.name.as_bytes(), keys)?;
    let notes = Cipher::encrypt(item.notes.as_bytes(), keys)?;

    let collection_ids: Vec<String> = collection_id.into_iter().map(|x| x.to_owned()).collect();

    // Bitwarden wants base64-encoded SHA256 hashes of uris
    let uri_checksum = base64::prelude::BASE64_STANDARD
        .encode(sha2::Sha256::new_with_prefix(item.uri.as_bytes()).finalize());
    let uri_checksum = Cipher::encrypt(uri_checksum.as_bytes(), keys)?;

    let uri_object = LoginItemUri {
        uri: uri.clone(),
        uri_match: None,
        uri_checksum,
    };

    let item = CipherItem {
        collection_ids,
        id: String::default(),
        name,
        notes,
        organization_id: org_id.map(|x| x.to_owned()),
        key: None,
        favorite: false,
        data: CipherData::Login(Box::new(bitwarden::api::LoginItem {
            username,
            password,
            uri,
            uris: Some(vec![uri_object]),
        })),
    };

    let personal_cipher = item.into();
    let collection_ids = collection_id.into_iter().map(|x| x.to_owned()).collect();
    Ok(CreateOrgCipherRequest {
        cipher: personal_cipher,
        collection_ids,
    })
}

fn encrypt_note(
    keys: &EncMacKeys,
    item: &NoteItem,
    collection_id: Option<&str>,
    org_id: Option<&str>,
) -> Result<CreateOrgCipherRequest, CipherError> {
    let name = Cipher::encrypt(item.name.as_bytes(), keys)?;
    let notes = Cipher::encrypt(item.notes.as_bytes(), keys)?;

    let collection_ids: Vec<String> = collection_id.into_iter().map(|x| x.to_owned()).collect();

    let item = CipherItem {
        collection_ids,
        id: String::default(),
        name,
        notes,
        organization_id: org_id.map(|x| x.to_owned()),
        key: None,
        favorite: false,
        data: CipherData::SecureNote(Box::new(SecureNoteItem {
            secure_note_type: 0,
        })),
    };

    let personal_cipher = item.into();
    let collection_ids = collection_id.into_iter().map(|x| x.to_owned()).collect();
    Ok(CreateOrgCipherRequest {
        cipher: personal_cipher,
        collection_ids,
    })
}
