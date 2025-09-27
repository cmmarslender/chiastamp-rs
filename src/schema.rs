// @generated automatically by Diesel CLI.

diesel::table! {
    records (id) {
        id -> Unsigned<Integer>,
        #[max_length = 32]
        hash -> Binary,
        batch_id -> Nullable<Unsigned<Integer>>,
        created_at -> Datetime,
        updated_at -> Datetime,
    }
}
