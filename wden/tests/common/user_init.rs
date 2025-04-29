use serde_json::json;
use std::{ops::Deref, sync::LazyLock};

use super::api::VaultwardenClient;

pub const PBKDF2_USER_EMAIL: &str = "test.pbkdf2@example.com";
pub const PBKDF2_USER_PASSWORD: &str = "testpassword";
pub const PBKDF2_USER_MASTER_PW_HASH: &str = "37P9C8QdJtPAtA6xhQLHveT27uJRdBnWjftXyrl68d4=";
pub const PBKDF2_USER_KEY_CIPHER: &str = "2.hX9oAwd/pchQFFdnm2Xmig==|a2pevv+lnbXzHZRgW55SmKqRwXTco6TAlhBYxjG2HohtELw4vlkZysi46o4xTpm7g19xWTNT/g0Wp+K6OE04Kko3r8Hc/vgJqjRWbKSOZ1M=|Ro/5lE6yVNer1ABxC74vELBDafbj/B9XDpv+rxrGavE=";

static PBKDF2_TEST_USER_JSON: LazyLock<serde_json::Value> = LazyLock::new(|| {
    json!({
        "email": PBKDF2_USER_EMAIL,
        "name": "Pbkdf2 Test User",
        "masterPasswordHash": PBKDF2_USER_MASTER_PW_HASH,
        "key": PBKDF2_USER_KEY_CIPHER,
        "referenceData":{"id":null,"initiationPath":"Registration form"},
        "captchaResponse":null,
        "kdf":0,
        "kdfIterations":600000,
        "masterPasswordHint":"test password without space",
        "keys":{
            "publicKey":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0O3RmsohrnoRo2fajfgJFvuxRrCT7auRYNly5kiDUCOw9DATfghTZ6ZK2x9yQr8ChweHlpi5dXSp7BConMtEtRVUR8GVeUp0O8oOts1zarvjlS1LjvAAMYQOepJUIQQNJ4O9vjCF2wZQxJv0t9hwEsP8I+rw0fXi8hnjeYaFbsVjhv/MdZj1Ck3YhCNaXCuYmYM0PLyZc+otP+DE5wxm9ZNnyNQRXMzBZzULeiRyvkF9sTNj6wYK8HBp0DDTBgU9tM135ma+rSJ1rHKUHmGjMWkgk4XX7NgMNWVZW6iF69qaip0PLkpZiBa30Hf8lDWL/UofaGtIfN5uuSPEfttr9wIDAQAB",
            "encryptedPrivateKey":"2.KRu3XrPcv7PKDuyL5ovhTg==|QhTSZc/tMrl8cLlAJ5qKE3be9Y6h7phZsUj3lF59ki7qmlKSzPjVhnuQ2Kzhcmx7DyHGYl56WjUNhKSDgUUlN0ZMtYz/mgbgq2PfGE/r3tKOqFf+92XbAxY15aZmiKh+YSZ8GDmURq38hHvOhQNaQ+D63Czut0Cp//V166sqZbE2lCaTa7KSVYkZ9pJNVvDLZVdOYacSZ/UemfXzl68+o2ICR6bzs4VbxSXzm6VS5GOyw4EtktB8SOmeSefQwzS/L3ab5poX3/rrYXJV9oVCfEzx9NaHA5WXdiHqge2vBhncmP91LrL7E4obx80Q4QdW2UIvV9BPFH9ibs/YJLXFwxfO9JO4bgGP9kTA+Hmc0fP1A+hXyTfPl/TcVF1SyuBBEYPkPCDSv1winYKhmCrMJXODRQLUrvymDBliLmj2FQANvtjzKA/OuoLJ7cr1WeVcrWYaDfEiZ1o5xVsor9OWvqxErUDm6nJ19Vq8yqwah3pKBhyKHhJ6Xw1zzPg/QyOlsmhvVvKsu3FR3j44QhkV611yXq9aHUJ+JNV9eMZx+lKOpFMHTW/lQzvUKQQwng8UT9qEIceaYTS4Jv7OkESMQzWJWjgDyhgKDUR/o7lKru0t3co3ZttoHplsrZMF+lLZtw4wQj+9EGbG2rJwVZmg7cFWK+SONFNBaVgcxYOSJ2QJZYEfQl0rlUIskiT5JO9LFC/+Uo0HdeTWdYRnwuLcK3h01YqFvbxcWFttfbjaPT5hgZR44466R3/CltJmTrs6ZY8bKADVc+2tuSkw1VB4u6N03OOTKi2p26Od79EbJuGHgR6wxyGc0X7/fL/8CV4OHMsql0zNkHraj18/HaEDWzDnB/KCxwzp3Cz7gd9LDwS1PMjvtjYXfTWdHVFO/Dutw2BMgI8DHuWOh8+H6UMfRad1x8pboVdPPdqojB+mzCrudVONvwLstlL/A8ZxL2/jmoQq5EsaKebuYEkSMLZ5qaaUkxqhhW6t9b9HMpJfMDY+ms9SFVcpBRrQJy5MaOt5oc1zDb7bgjobnBvhV/lcJXIG8D9hgvsimnVt9GKDAhoquDFufL/4uZB3qrfBujxpHgXSnQTxIyfkaEuR2ipGkRc5MP3Bhkwm1KeeGC56Ld2jxgqL1TNaH7/yjFvmpRtP3wzU1ch4/8q3XXPuupYprvZigy9RPeTrXH9/JtnHCmP3r1rvTXy1oHlkdlJSdP9ICPCXzDRrITJld6G9taOFWYlQDvN6VtodXFpZlV1uWua6fg+4b4ymrgER7N6JoUsuz5uDTsnXqSaRCYwAUtaWt4tj3V+FJq3NEZrrmEKKll44Ek4gy8eVx74i87omzmkEJUymFi3AJaTq0Q0rVfTkIsz36CEdP80Q6dADw63ulygjPFMHXnUNUpMxMXB60v4CAuVxB4VbFmhR20kZcDro39A0KcXPjyuXMLOs8r+G32eruFJvwsgfnqKHeNJ7gbdGS/DtWtmqc9AmUZpDwhkT+3+thA6q3tLYdPH+TWGgbJr+LQ3v+qQMyjA3S9TZnvFevXMwcxFDexclrElUU/E5R0wyQHQNtzry1xfdNvWSFjQ3hXt1giZPvud412v2b/GgrkFphhzH0CtAGi9CYZKgs7k6KmpaT950F8u08OThYb0=|W9LGzSda4jsxgN1oiaywKyp0KV2hNFCbVU2vSkaO+io="
        }
    })
});

pub async fn init_users(client: &VaultwardenClient) -> anyhow::Result<()> {
    client
        .post("/identity/accounts/register", PBKDF2_TEST_USER_JSON.deref())
        .await?;
    Ok(())
}
