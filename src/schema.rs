// @generated automatically by Diesel CLI.

diesel::table! {
    password (id) {
        id -> Integer,
        user_id -> Integer,
        name -> Text,
        username -> Nullable<Text>,
        email -> Nullable<Text>,
        key -> Nullable<Text>,
        notes -> Nullable<Text>,
        kdf_salt -> Nullable<Text>,
        kdf_iterations -> Nullable<Integer>,
        aes_nonce -> Nullable<Text>,
    }
}

diesel::table! {
    user (id) {
        id -> Integer,
        username -> Text,
        password -> Text,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    password,
    user,
);
