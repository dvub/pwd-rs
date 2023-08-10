// @generated automatically by Diesel CLI.

diesel::table! {
    password (id) {
        id -> Integer,
        name -> Text,
        username -> Nullable<Text>,
        email -> Nullable<Text>,
        pass -> Nullable<Text>,
        notes -> Nullable<Text>,
        aes_nonce -> Nullable<Text>,
    }
}
