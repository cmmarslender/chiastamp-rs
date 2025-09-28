use chrono::NaiveDateTime;
use diesel::prelude::*;

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = crate::schema::records)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub struct Record {
    pub id: u32,
    pub hash: Vec<u8>,
    pub batch_id: Option<u32>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::records)]
pub struct NewRecord<'a> {
    pub hash: &'a [u8],
}

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = crate::schema::batches)]
#[diesel(check_for_backend(diesel::mysql::Mysql))]
pub struct Batch {
    pub id: u32,
    pub root_hash: Vec<u8>,
    pub spent_coin: Vec<u8>,
    pub block_hash: Option<Vec<u8>>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::batches)]
pub struct NewBatch<'a> {
    pub root_hash: &'a [u8],
    pub spent_coin: &'a [u8],
}
