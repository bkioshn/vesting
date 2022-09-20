use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Timestamp};
use cw_storage_plus::{Item, Map};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub owner: Addr,
    pub starting_time: Timestamp
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct VestingInfo {
    pub reward: u128,
    pub counter: u8,
    pub approve_tollgate_time: Timestamp,
}


pub const CONFIG: Item<Config> = Item::new("config");
// user address -> reward amount (_,_)
// pub const VESTING_INFO: Map<Addr,u128> = Map::new("vesting_info");

// user address -> (reward, counter, approve_tollgate_time)
pub const VESTING_INFO: Map<Addr, VestingInfo> = Map::new("vesting_info");
// Approve per user
// pub const APPROVE_TOLLGATE_TIME: Item<Timestamp> = Item::new("approve_tollgate_time");

// pub const CLAIM_COUNTER: Map<Addr, u64> = Map::new("claim_counter");