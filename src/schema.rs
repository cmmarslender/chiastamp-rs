// @generated automatically by Diesel CLI.

diesel::table! {
    batches (id) {
        id -> Unsigned<Integer>,
        #[max_length = 32]
        root_hash -> Binary,
        #[max_length = 32]
        spent_coin -> Binary,
        #[max_length = 32]
        block_hash -> Nullable<Binary>,
        created_at -> Datetime,
        updated_at -> Datetime,
    }
}

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

diesel::allow_tables_to_appear_in_same_query!(batches, records,);
