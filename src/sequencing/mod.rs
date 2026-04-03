pub mod erm41;
pub mod jsondata;

use erm41::Erm41Position28;



#[derive(Clone, Debug)]
pub struct SeqData {
    pub ab1_call_opt: Option<Erm41Position28>,
}