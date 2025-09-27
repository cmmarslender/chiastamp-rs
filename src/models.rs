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
